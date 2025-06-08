# Vybe Flow

Vybe Flow is a social networking application that allows users to register, log in, and share posts with images and captions. The application is built using Flask and SQLite, providing a simple yet functional platform for users to connect and share their experiences.

## Features

- User registration and authentication
- Upload images with captions
- View a feed of posts from all users
- Secure session management
- Responsive design with HTML templates

## Setup Instructions

1. **Clone the repository:**
   ```
   git clone <repository-url>
   cd vybe-flow
   ```

2. **Create a virtual environment:**
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install dependencies:**
   ```
   pip install -r requirements.txt
   ```

4. **Run the application:**
   ```
   python app.py
   ```

5. **Access the application:**
   Open your web browser and go to `http://127.0.0.1:5000`.

## Usage Guidelines

- **Registration:** Navigate to the registration page to create a new account.
- **Login:** Use your credentials to log in to your account.
- **Upload Posts:** After logging in, you can upload images with captions to share with other users.
- **View Feed:** The feed displays all posts from users, allowing you to see what others are sharing.

## Database

The application uses SQLite for data storage. The database file `vybeflow.db` will be created automatically upon running the application for the first time. 

## Directory Structure

```
vybe-flow
├── app.py                # Main application file
├── requirements.txt      # Project dependencies
├── README.md             # Project documentation
├── vybeflow.db           # SQLite database file
├── static                # Directory for static files
│   └── uploads           # Directory for uploaded images
├── templates             # Directory for HTML templates
│   ├── base.html         # Base template
│   ├── feed.html         # Feed display template
│   ├── login.html        # Login form template
│   ├── register.html     # Registration form template
│   └── upload.html       # Upload post form template
```

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue for any suggestions or improvements.