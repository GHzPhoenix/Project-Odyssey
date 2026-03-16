# Travel Odyssey - Project Overview

## Description

Travel Odyssey is a full-stack travel booking platform designed to offer personalized travel planning and booking experiences. It includes user authentication, booking management, and a customizable front-end for travel enthusiasts. The platform supports a range of travel services, including hotel bookings, trip planning, and membership options for exclusive benefits.

## Features

- User Authentication (Registration, Login, JWT)
- Personalized Trip Planning
- Custom Membership Options
- Secure Data Handling with PostgreSQL
- Dynamic Frontend with HTML, CSS, and JavaScript
- Backend APIs with Node.js and Express.js

## Technologies Used

### Frontend:

- HTML, CSS, JavaScript
- Bootstrap for responsive design

### Backend:

- Node.js, Express.js
- PostgreSQL for database management
- bcrypt for password hashing
- JWT for secure authentication

## Project Structure

```
Project-Odyssey-main/
│
├── backend/
│   ├── server.js          # Main server file
│   ├── routes/
│   │   ├── auth.js        # User authentication routes
│   │   └── booking.js     # Booking routes
│   ├── models/
│   │   └── User.js        # User model
│   ├── db.js              # Database connection
│   └── .env               # Environment variables
│
├── frontend/
│   ├── index.html         # Main landing page
│   ├── city.html          # City information page
│   ├── client-area.html   # User dashboard
│   ├── trip pages         # Individual trip pages
│   ├── css/
│   │   ├── style.css      # Main styles
│   │   └── membership.css # Membership page styles
│   ├── js/
│   │   └── script.js      # Frontend logic
│   └── assets/            # Images and logos
│
└── README.md              # Project documentation
```

## Setup Instructions

1. Clone the project

```
git clone https://github.com/YOUR_USERNAME/Project-Odyssey.git
```

2. Navigate to the backend directory and install dependencies:

```
cd Project-Odyssey-main/backend
npm install
```

3. Set up the PostgreSQL database:

- Create a new database.
- Run the provided SQL scripts to set up the necessary tables.

4. Configure the .env file with your database credentials:

```
PORT=5000
DATABASE_URL=postgres://user:password@localhost:5432/yourdatabase
JWT_SECRET=your_jwt_secret
```

5. Run the backend server:

```
npm start
```

6. Open the frontend in your browser:

```
http://localhost:5000
```

## License

MIT License
