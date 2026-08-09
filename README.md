# Quiz Management & Online Assessment Platform

A full-stack web application where Admins create and manage quizzes, and Students take them with automatic scoring and results.

**Live API:** https://quiz-platform-backend-fpkx.onrender.com

## Tech Stack
- **Frontend:** React.js, Tailwind CSS
- **Backend:** Node.js, Express.js
- **Database:** PostgreSQL (hosted on Render)
- **Auth:** JWT (JSON Web Tokens), bcrypt password hashing
- **Security:** helmet (secure headers), express-rate-limit

## Features
- Student & Admin authentication (register/login)
- Role-based authorization (Admin vs Student)
- Admin dashboard with platform statistics and analytics
- Student/user management
- Quiz management (create, edit, delete, publish/unpublish)
- Category management
- Question & options management (multiple choice)
- Quiz attempt system with server-validated scoring
- Detailed results with answer review
- Student dashboard with performance stats
- Leaderboard (overall and category-wise)

## Repositories
- Backend: https://github.com/sharanyam26/quiz-platform-backend
- Frontend: https://github.com/sharanyam26/quiz-platform-frontend

## Setup (local development)

### Backend
```bash
cd backend
npm install
# Create a .env file with PORT, DATABASE_URL, JWT_SECRET
npm run dev