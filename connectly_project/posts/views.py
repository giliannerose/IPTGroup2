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
from .permissions import IsPostAuthor
from rest_framework.authentication import TokenAuthentication

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
                    return JsonResponse({'message': 'Authentication successful!'})
                else:
                    return JsonResponse({'error': 'Invalid credentials'}, status=401)

            except Exception as e:
                return JsonResponse({'error': str(e)}, status=400)


#DataHandling




class PostListCreate(APIView):
    def get(self, request):
        posts = Post.objects.all()
        serializer = PostSerializer(posts, many=True)
        return Response(serializer.data)


    def post(self, request):
        serializer = PostSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CommentListCreate(APIView):
    def get(self, request):
        comments = Comment.objects.all()
        serializer = CommentSerializer(comments, many=True)
        return Response(serializer.data)


    def post(self, request):
        serializer = CommentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PostDetailView(APIView):
    permission_classes = [IsAuthenticated, IsPostAuthor]


    def get(self, request, pk):
        post = Post.objects.get(pk=pk)
        self.check_object_permissions(request, post)
        return Response({"content": post.content})


class ProtectedView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": "Authenticated!"})
    
class PostDetail(APIView):
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
        serializer = PostSerializer(post, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def delete(self, request, pk):
        post = self.get_object(pk)
        self.check_object_permissions(request, post)
        post.delete()
        return Response(
            {"message": "Post deleted successfully"},
            status=status.HTTP_204_NO_CONTENT
        )
