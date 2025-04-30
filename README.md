# Travel Odyssey - Project Overview

## Description
Travel Odyssey is a web-based travel booking platform that allows users to register, log in, and book their dream trips. Users can specify destinations, dates, guests, and preferences, and the data is securely stored using PostgreSQL.

## Features
- User authentication (register/login)
- Booking creation and retrieval
- Secure password hashing and JWT authentication
- Responsive frontend with HTML/CSS/JS
- Backend built with Node.js and Express

## Technologies
- Frontend: HTML, CSS, JavaScript
- Backend: Node.js, Express.js
- Database: PostgreSQL
- Auth: bcrypt, JWT

## Setup Instructions
1. Clone the project
2. Install dependencies with `npm install`
3. Set up your `.env` file with database credentials
4. Run the server: `node index.js`
5. Use PostgreSQL to import `schema.sql` and create tables

## Folder Structure
```
/project-root
│
├── backend/
│   ├── index.js
│   ├── .env
│   └── schema.sql
│
├── frontend/
│   ├── index.html
│   ├── city.html
│   ├── client-area.html
│   ├── signup.html
│   ├── script.js
│   ├── style.css
│   └── login.css
│
├── README.md
```

## License
MIT License