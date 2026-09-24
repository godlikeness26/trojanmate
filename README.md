# TrojanMate
Multi-platform peer tutoring and academic support system for Trimex Colleges.

## Included modules
- Student/tutor/admin authentication
- Tutor registration and admin verification
- Tutor profiles, subjects, expertise, availability and ratings
- Tutor search/filtering
- Booking and schedule management
- Tutoring session records
- Feedback and ratings
- Basic compensation/payment status tracking
- Admin dashboard and records

## Tech stack
Python + Flask + SQLite + HTML/CSS/JavaScript.

## Run in VS Code
1. Open this folder in VS Code.
2. Create a terminal.
3. Create a virtual environment:
   `python -m venv .venv`
4. Activate it on Windows:
   `.venv\Scripts\activate`
5. Install:
   `pip install -r requirements.txt`
6. Start:
   `python app.py`
7. Open:
   `http://127.0.0.1:5000`

The database is created automatically as `trojanmate.db`.

## Demo admin
Email: `admin@trojanmate.local`
Password: `Admin123!`

Change the demo password before deployment.

## Notes
This is a working thesis-project prototype. It intentionally does not implement AI-based tutor matching, predictive analytics, or large-scale institutional deployment, which are outside the stated scope of the study.
