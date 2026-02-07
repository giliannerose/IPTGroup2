from django.urls import path
from . import views
from .views import PostListCreate, CommentListCreate, PostDetail,  CommentDetail
from .views import ProtectedView


urlpatterns = [
    
    #USERS
    path('users/', views.list_users, name='list-users'),
    path('users/create/', views.create_user, name='create-user'),
    path('users/<int:user_id>/update/', views.update_user, name='update-user'),
    path('users/<int:user_id>/delete/', views.delete_user, name='delete-user'),
 

    
    #LOGIN
    path('login/', views.login_user, name='login'),
    
    #Posts
    path('posts/', PostListCreate.as_view(), name='post-list-create'),
    path('posts/<int:pk>/', PostDetail.as_view(), name='post-detail'),
    
    #comments
    path('comments/', CommentListCreate.as_view(), name='comment-list-create'),
    path('comments/<int:pk>/', CommentDetail.as_view(), name='comment-detail'),

    
    #protected
    path('protected/', ProtectedView.as_view(), name='protected'),

]
