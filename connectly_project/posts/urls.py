from django.urls import path
from . import views
from .views import PostListCreate, CommentListCreate
from .views import ProtectedView


urlpatterns = [
    path('users/', views.list_users, name='list-users'),
    path('users/create/', views.create_user, name='create-user'),
    path('users/<int:user_id>/update/', views.update_user, name='update-user'),
    path('users/<int:user_id>/delete/', views.delete_user, name='delete-user'),
 

    
    
    path('login/', views.login_user, name='login'),
    path('posts/', PostListCreate.as_view(), name='post-list-create'),
    path('comments/', CommentListCreate.as_view(), name='comment-list-create'),
    path('protected/', ProtectedView.as_view(), name='protected'),

]
