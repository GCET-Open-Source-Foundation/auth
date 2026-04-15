#**otp.go**

This code implements a complete One-Time Password (OTP) authentication system for email. It handles the full lifecycle of an OTP: generating a secure code, saving it to a database, emailing it to the user, verifying it, and automatically cleaning up expired codes.

**generateOTP()**
Why it’s used: Security & Unpredictability
Cryptographic Security: It uses crypto/rand instead of standard math libraries. This ensures the 6-digit code is truly random and cannot be predicted by an attacker using mathematical patterns.
Standardization:It ensures the code is always exactly 6 digits (using %06d padding). Without this, a random number like 42 would be sent as 42 instead of the expected 000042, which would confuse users.

**SendOTP()**
Why it’s used: The "Initiator"
Identity Verification: This is the bridge between your app and the user's real-world identity (their email). It proves the person trying to log in actually has access to that email inbox.
State Management:It uses an "Upsert" (Update or Insert) logic. This is used so that if a user clicks "Resend Code" multiple times, the database doesn't get cluttered with 10 different codes for one person—it simply replaces the old one with the newest, valid one.

**VerifyOTP()**
Why it’s used: Access Control & Attack Prevention
The Gatekeeper: This is the actual "lock" on the door. It ensures that only users with the correct, current code can proceed.
Expiration Enforcement: It checks the timestamp to ensure security. An OTP shouldn't be valid forever; if a hacker finds an old email from three days ago, this function ensures that code is useless.
Anti-Replay (One-Time Use): It deletes the code immediately after a successful login. This is used so that a code cannot be intercepted and used a second time by someone else.
How it works: When a code is generated in SendOTP, a timestamp is saved in the expires_at column (set to Current Time + 5 minutes).If the user attempts to verify even one second after the 5-minute mark, the function returns false and treats the code as non-existent, even if the 6-digit numbers match perfectly.

**startOTPCleanup()**
Why it’s used: Database Hygiene & Performance
Automated Maintenance: Many users will request a code but never actually type it in (they change their mind or get distracted). Without this function, your database table (otps) would grow larger and larger every day with "dead" data.
Efficiency: By deleting expired codes every 5 minutes, it keeps the database table small and the search queries fast.
Resource Management: It uses a select statement with a.ctx.Done(). This is used to ensure that when your server stops, the background "timer" also stops, preventing "goroutine leaks" (orphaned processes running in the background).

