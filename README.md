# Password Strength Checker

A Python-based tool that checks password strength using **length, character variety, entropy, common password detection, repeated patterns, and keyboard sequences**.

## Features

* Scores passwords from **0 to 4**
* Labels strength as **Very Weak, Weak, Moderate, Strong, Very Strong**
* Calculates **entropy**
* Detects:

  * Common weak passwords
  * Repeated characters/sequences
  * Keyboard patterns like `qwerty`
* Provides improvement feedback
* Includes secure string comparison using `hmac.compare_digest()`

## Requirements

* Python 3.x
* No external libraries required

## Run the Program

```bash
python password_strength_checker.py
```

## Example

```bash
Enter password: Hello@123

Strength: Strong (score 3/4)
Entropy: 58.95 bits
Length: 9 characters
```

## Output

The checker returns:

* **score**
* **strength**
* **entropy**
* **length**
* **feedback**

## Security Checks Used

* Minimum/recommended length
* Lowercase, uppercase, digits, symbols
* Entropy estimation
* Common password blacklist
* Repeated and sequential pattern detection
* Keyboard sequence detection

## Note

This project is for **educational and cybersecurity training purposes**.
