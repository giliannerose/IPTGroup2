from ..models import Post

class PostFactory:

    @staticmethod
    def create_post(author, content):
        if not content or not content.strip():
            raise ValueError("Post content cannot be empty")

        return Post.objects.create(
            author=author,
            content=content
        )
