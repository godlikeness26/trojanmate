# TrojanMate – Booking Tickets, Payments, and Reports

This update is based on the current TrojanMate verification-fixed project.

## Booking tickets
Each new booking receives a permanent ticket number such as `TM-2026-000012`. The ticket contains:
- Student and tutor
- Subject
- Session date and time
- Session fee
- Booking status
- Payment status
- Request note

Existing bookings receive ticket numbers automatically through the startup migration.

## Payment flow
1. Tutor confirms the booking.
2. Student opens the ticket and selects **I Have Paid**.
3. Payment changes to **Awaiting Tutor Confirmation**.
4. Tutor sees **Student Says Paid** and can select **Confirm Payment**.
5. Payment becomes **Paid & Confirmed**.

## Reports / disputes
Both the student and tutor can report a booking issue from the ticket. Available reasons include:
- Payment dispute
- Booking or cancellation issue
- No-show
- Inappropriate behavior
- Service/session issue
- Other

Submitting a report creates an administrator notification. Administrators have a **Reports / Disputes** view where they can review the ticket, reporter, reason, description, and change the report status to Open, Reviewing, Resolved, or Dismissed with an admin note.

## Database safety
The update uses migrations and does not delete or recreate the existing SQLite database. New columns and the `booking_reports` table are added automatically.
