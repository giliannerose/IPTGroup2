import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.contrib.auth import authenticate

from .models import Post, Comment
from .serializers import PostSerializer, CommentSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from .permissions import IsPostAuthor, IsCommentAuthor
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from .singletons.logger_singleton import LoggerSingleton
from .factories.post_factory import PostFactory
from .models import Like
from rest_framework.pagination import PageNumberPagination
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from django.conf import settings
import requests
from django.conf import settings

logger = LoggerSingleton().get_logger()

logger.info("API initialized successfully.")



def list_users(request):
    try:
        users = list(User.objects.values('id', 'username', 'email', 'date_joined'))
        return JsonResponse(users, safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def create_user(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)

            if User.objects.filter(username=data['username']).exists():
                return JsonResponse(
                    {'error': 'Username already exists'},
                    status=400
                )

            user = User.objects.create_user(
                username=data['username'],
                email=data.get('email'),
                password=data['password']
            )

            return JsonResponse(
                {'id': user.id, 'message': 'User created successfully'},
                status=201
            )

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
def update_user(request, user_id):
    if request.method == 'PUT':
        try:
            data = json.loads(request.body)
            user = User.objects.get(id=user_id)

            user.username = data.get('username', user.username)
            user.email = data.get('email', user.email)
            user.save()

            return JsonResponse(
                {'message': 'User updated successfully'},
                status=200
            )

        except User.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)


@csrf_exempt
def delete_user(request, user_id):
    if request.method == 'DELETE':
        try:
            user = User.objects.get(id=user_id)
            user.delete()

            return JsonResponse(
                {'message': 'User deleted successfully'},
                status=200
            )

        except User.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)


def get_posts(request):
    try:
        posts = list(Post.objects.values('id', 'content', 'author', 'created_at'))
        return JsonResponse(posts, safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def create_post(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            author = User.objects.get(id=data['author'])
            post = Post.objects.create(content=data['content'], author=author)
            return JsonResponse({'id': post.id, 'message': 'Post created successfully'}, status=201)
        except User.DoesNotExist:
            return JsonResponse({'error': 'Author not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
        

  #login      


@csrf_exempt
def login_user(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)

            user = authenticate(
                username=data['username'],
                password=data['password']
            )

            if user is not None:
                token, _ = Token.objects.get_or_create(user=user)
                
                logger.info(f"User logged in: {user.username}") #logger
                  
                return JsonResponse({
                    "message": "Authentication successful!",
                    "token": token.key
                })
            else:
                
                logger.warning(f"Failed login attempt for username: {data.get('username')}")
                
                return JsonResponse({'error': 'Invalid credentials'}, status=401)

        except Exception as e:
            
            logger.error(f"Login error: {str(e)}")
            
            return JsonResponse({'error': str(e)}, status=400)



#DataHandling




class PostListCreate(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        posts = Post.objects.all()
        serializer = PostSerializer(posts, many=True)
        return Response(serializer.data)

    def post(self, request):
        try:
            post = PostFactory.create_post(
                author=request.user,
                content=request.data.get("content")
            )

            serializer = PostSerializer(post)

            logger.info(f"Post created by {request.user.username}")

            return Response(serializer.data, status=status.HTTP_201_CREATED)

        except ValueError as e:
            logger.warning(
                f"Post creation failed for user {request.user.username}: {str(e)}"
            )
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )



class CommentListCreate(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        comments = Comment.objects.filter(post__author=request.user)
        serializer = CommentSerializer(comments, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = CommentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(author=request.user)  
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProtectedView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": "Authenticated!"})
    

class PostDetail(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated, IsPostAuthor]

    def get_object(self, pk):
        return Post.objects.get(pk=pk)

    def get(self, request, pk):
        post = self.get_object(pk)
        self.check_object_permissions(request, post)
        serializer = PostSerializer(post)
        return Response(serializer.data)

    def put(self, request, pk):
        post = self.get_object(pk)
        self.check_object_permissions(request, post)
        serializer = PostSerializer(post, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def delete(self, request, pk):
        post = self.get_object(pk)
        self.check_object_permissions(request, post)
        post.delete()
        
        logger.info(f"Post deleted by {request.user.username} (post_id={pk})")
         
        return Response(
            {"message": "Post deleted successfully"},
            status=status.HTTP_200_OK
        )

class CommentDetail(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated, IsCommentAuthor]

    def get_object(self, pk):
        return Comment.objects.get(pk=pk)

    def get(self, request, pk):
        comment = self.get_object(pk)
        self.check_object_permissions(request, comment)
        serializer = CommentSerializer(comment)
        return Response(serializer.data)

    def put(self, request, pk):
        comment = self.get_object(pk)
        self.check_object_permissions(request, comment)
        serializer = CommentSerializer(comment, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def delete(self, request, pk):
        comment = self.get_object(pk)
        self.check_object_permissions(request, comment)
        comment.delete()
        return Response(
            {"message": "Comment deleted successfully"},
            status=status.HTTP_200_OK
        )

class PostLikeView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            post = Post.objects.get(pk=pk)

            like, created = Like.objects.get_or_create(
                user=request.user,
                post=post
            )

            if not created:
                return Response(
                    {"message": "You already liked this post"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            return Response(
                {"message": "Post liked successfully"},
                status=status.HTTP_201_CREATED
            )

        except Post.DoesNotExist:
            return Response(
                {"error": "Post not found"},
                status=status.HTTP_404_NOT_FOUND
            )
            
class PostCommentView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            post = Post.objects.get(pk=pk)

            comment = Comment.objects.create(
                text=request.data.get("text"),
                author=request.user,
                post=post
            )

            serializer = CommentSerializer(comment)
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        except Post.DoesNotExist:
            return Response(
                {"error": "Post not found"},
                status=status.HTTP_404_NOT_FOUND
            )
            
class PostCommentListView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        try:
            post = Post.objects.get(pk=pk)
            comments = post.comments.all().order_by('-created_at')

            paginator = PageNumberPagination()
            paginator.page_size = 5
            result_page = paginator.paginate_queryset(comments, request)

            serializer = CommentSerializer(result_page, many=True)
            return paginator.get_paginated_response(serializer.data)

        except Post.DoesNotExist:
            return Response(
                {"error": "Post not found"},
                status=status.HTTP_404_NOT_FOUND
            )
            
class GoogleLoginView(APIView):

    def post(self, request):
        token = request.data.get("id_token")

        if not token:
            return Response(
                {"error": "No id_token provided"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
    
            idinfo = id_token.verify_oauth2_token(
                token,
                google_requests.Request(),
                "404307887594-40cvf73hklo2nm48vtjk210fkh54a2md.apps.googleusercontent.com"  
            )

            email = idinfo.get("email")
            name = idinfo.get("name")

            if not email:
                return Response(
                    {"error": "Google account has no email"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Create or get user
            user, created = User.objects.get_or_create(
                email=email,
                defaults={"username": email.split("@")[0]}
            )

            token_obj, _ = Token.objects.get_or_create(user=user)

            return Response({
                "message": "Google login successful",
                "token": token_obj.key,
                "email": user.email
            })

        except ValueError as e:
            return Response(
                {
                    "error": "Invalid or expired Google token",
                    "details": str(e)
                },
                status=status.HTTP_400_BAD_REQUEST
            )
           
                      


class GoogleCallbackView(APIView):

    def get(self, request):
        code = request.GET.get("code")

        if not code:
            return Response(
                {"error": "No authorization code provided"},
                status=400
            )

        token_url = "https://oauth2.googleapis.com/token"

        data = {
            "code": code,
            "client_id": "404307887594-40cvf73hklo2nm48vtjk210fkh54a2md.apps.googleusercontent.com",
            "client_secret": "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",
            "redirect_uri": "https://melanie-semiformal-delinda.ngrok-free.dev/posts/auth/google/callback/",
            "grant_type": "authorization_code",
        }

        token_response = requests.post(token_url, data=data)

        if token_response.status_code != 200:
            return Response(
                {
                    "error": "Google token exchange failed",
                    "google_response": token_response.json()
                },
                status=status.HTTP_400_BAD_REQUEST
    )

        token_json = token_response.json()
        google_id_token = token_json.get("id_token")

        if not google_id_token:
            return Response(
                {"error": "No id_token received"},
                status=400
            )
            
    

        from google.oauth2 import id_token
        from google.auth.transport import requests as google_requests

        try:
            idinfo = id_token.verify_oauth2_token(
                google_id_token,
                google_requests.Request(),
                "404307887594-40cvf73hklo2nm48vtjk210fkh54a2md.apps.googleusercontent.com"
            )

            email = idinfo.get("email")

            user, created = User.objects.get_or_create(
                email=email,
                defaults={"username": email.split("@")[0]}
            )

            token_obj, _ = Token.objects.get_or_create(user=user)

            return Response({
                "message": "Google login successful",
                "token": token_obj.key,
                "email": user.email
            })

        except ValueError:
            return Response(
                {"error": "Invalid ID token"},
                status=400
            )