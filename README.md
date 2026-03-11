# Connectly API - Milestone 2 (Group 2)

**Branch with final version:** `milestone-2`  
**Live Demo:** Run `python manage.py runserver 8001` → test `/feed/`

## Features Implemented
- Likes & Comments with duplicate prevention
- Paginated comments per post
- Google OAuth login (ID token validation)
- **News Feed endpoint** (`GET /feed/`) – sorted by newest + pagination (HW7)
- Token Authentication + protected routes

## AI Disclosure Statement
This project was developed collaboratively by the team. We used several AI tools as assistants and debugging aids, not as replacements for our own coding and problem-solving.

AI Tools Used:
- ChatGPT
- Gemini
- Microsoft Copilot

How AI Was Used:
- Debugging errors we could not immediately understand (like ImportError, SSL, 301 redirect, and token authentication issues)
- Explaining complex Django REST Framework concepts
- Suggesting fixes for HTTPS setup, token authentication, pagination, and Postman issues
- Guiding Postman testing and HTTPS/HTTP fixes
- Helping with code explanations when we were stuck
- Correctly placing the `/feed/` endpoint at root level
- Cleaning the repository (removing .pem files, fixing .gitignore)

All final code and decisions were reviewed and approved by the team.
