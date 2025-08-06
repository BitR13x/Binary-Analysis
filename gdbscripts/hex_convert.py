#!/usr/bin/env python3
"""
Flexible Multi-format Hex Converter with Arrow Navigation
Handles: 0x41414141, 0x410x410x41, 41 41 41, 0x41 0x41 0x41
Displays results on new line
"""

import sys
import termios
import tty
import re
import os


def parse_hex_input(hex_input):
    """Parse various hex input formats into individual bytes"""
    if not hex_input.strip():
        return []

    # Remove extra whitespace
    cleaned = hex_input.strip()

    # Pattern 1: 0x41414141 (long hex string with single 0x prefix)
    if cleaned.startswith("0x") and len(cleaned) > 2:
        hex_part = cleaned[2:]
        if all(c in "0123456789abcdefABCDEF" for c in hex_part):
            # Split into pairs
            bytes_list = []
            for i in range(0, len(hex_part), 2):
                if i + 1 < len(hex_part):
                    bytes_list.append(hex_part[i : i + 2])
                else:
                    bytes_list.append(hex_part[i] + "_")  # Incomplete byte
            return bytes_list

    # Pattern 2: 0x410x410x41 or 41 41 41 or 0x41 0x41 0x41
    # Split by spaces and/or 0x patterns
    parts = re.split(r"\s+|(?=0x)", cleaned)
    parts = [p for p in parts if p]  # Remove empty parts

    bytes_list = []
    for part in parts:
        part = part.strip()
        if not part:
            continue

        if part.startswith("0x"):
            hex_part = part[2:]
        else:
            hex_part = part

        # Validate hex characters
        if all(c in "0123456789abcdefABCDEF" for c in hex_part):
            if len(hex_part) == 1:
                bytes_list.append(hex_part + "_")  # Incomplete byte
            elif len(hex_part) == 2:
                bytes_list.append(hex_part)
            elif len(hex_part) > 2:
                # Split long hex strings into pairs
                for i in range(0, len(hex_part), 2):
                    if i + 1 < len(hex_part):
                        bytes_list.append(hex_part[i : i + 2])
                    else:
                        bytes_list.append(hex_part[i] + "_")

    return bytes_list


def convert_hex_bytes(hex_input):
    """Convert hex string to multiple bytes"""
    try:
        bytes_list = parse_hex_input(hex_input)

        if not bytes_list:
            return [], [], [], ""

        hex_values = []
        chars = []
        ints = []

        for byte_str in bytes_list:
            if byte_str.endswith("_"):
                # Incomplete byte
                hex_digit = byte_str[0]
                int_value = int(hex_digit, 16)
                hex_values.append(f"0x{hex_digit}_")
                chars.append(f"{hex_digit}_")
                ints.append(f"{int_value}_")
            else:
                # Complete byte
                int_value = int(byte_str, 16)
                hex_values.append(f"0x{byte_str.upper()}")

                # Convert to character
                if 32 <= int_value <= 126:  # Printable ASCII
                    char_value = chr(int_value)
                elif int_value == 0:
                    char_value = "\\0"
                elif int_value == 9:
                    char_value = "\\t"
                elif int_value == 10:
                    char_value = "\\n"
                elif int_value == 13:
                    char_value = "\\r"
                else:
                    char_value = "."

                chars.append(char_value)
                ints.append(str(int_value))

        return hex_values, chars, ints, ""

    except ValueError as e:
        return [], [], [], f"Invalid format: {str(e)}"


def clear_last_lines(n):
    for _ in range(n):
        sys.stdout.write("\033[F")  # Move cursor up
        sys.stdout.write("\033[K")  # Clear to the end of the line


def display_conversion(hex_input, cursor_pos):
    """Display the conversion results with cursor"""
    clear_last_lines(10)

    # Show input with cursor
    input_with_cursor = hex_input[:cursor_pos] + "|" + hex_input[cursor_pos:]
    print(f">> {input_with_cursor}", end="", flush=True)

    # If there's input, show conversion on next line
    if hex_input.strip():
        hex_values, chars, ints, error = convert_hex_bytes(hex_input)

        if error:
            print(f"\r\n   Error: {error}", end="", flush=True)
        elif hex_values:
            hex_str = " ".join(hex_values)
            char_str = " ".join(chars)
            int_str = " ".join(ints)

            sys.stdout.write(f"\r\nHex:  {hex_str}")
            sys.stdout.write(f"\r\nChar: {char_str}")
            sys.stdout.write(f"\r\nInts:  {int_str}")

            try:
                sys.stdout.write(f"\r\nInt: {int(hex_input, 16)}")
            except ValueError:
                sys.stdout.write("\r\nInt: Invalid input")

            sys.stdout.write("\r\n\r\n")


def read_arrow_key():
    """Read arrow key sequence"""
    char1 = sys.stdin.read(1)  # Should be '['
    if char1 == "[":
        char2 = sys.stdin.read(1)
        if char2 == "C":  # Right arrow
            return "RIGHT"
        elif char2 == "D":  # Left arrow
            return "LEFT"
        elif char2 == "A":  # Up arrow
            return "UP"
        elif char2 == "B":  # Down arrow
            return "DOWN"
    return None


def main():
    """Main interactive loop with arrow navigation"""
    os.system("clear")

    # Save terminal settings
    old_settings = termios.tcgetattr(sys.stdin)

    try:
        # Set terminal to raw mode
        tty.setraw(sys.stdin.fileno())

        current_input = ""
        cursor_pos = 0
        display_conversion(current_input, cursor_pos)

        while True:
            # Read single character
            char = sys.stdin.read(1)

            # Handle special keys
            if ord(char) == 27:  # ESC key or arrow keys
                arrow = read_arrow_key()
                if arrow == "LEFT":
                    cursor_pos = max(0, cursor_pos - 1)
                    display_conversion(current_input, cursor_pos)
                elif arrow == "RIGHT":
                    cursor_pos = min(len(current_input), cursor_pos + 1)
                    display_conversion(current_input, cursor_pos)
                elif arrow is None:  # Just ESC
                    break
            elif ord(char) == 3:  # Ctrl+C
                break
            elif ord(char) == 127 or ord(char) == 8:  # Backspace/Delete
                if cursor_pos > 0:
                    current_input = (
                        current_input[: cursor_pos - 1] + current_input[cursor_pos:]
                    )
                    cursor_pos -= 1
                    # Clear the conversion area
                    print("\n\n\n", end="", flush=True)
                    display_conversion(current_input, cursor_pos)
            elif ord(char) == 13 or ord(char) == 10:  # Enter - clear input
                current_input = ""
                cursor_pos = 0
                print("\n\n\n\n")  # Clear conversion area and move to new line
                display_conversion(current_input, cursor_pos)
            elif (
                char.isprintable() and len(current_input) < 100
            ):  # Allow printable characters
                # Insert character at cursor position
                current_input = (
                    current_input[:cursor_pos] + char + current_input[cursor_pos:]
                )
                cursor_pos += 1
                display_conversion(current_input, cursor_pos)

    except KeyboardInterrupt:
        pass
    finally:
        # Restore terminal settings
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        print("\n\n\nGoodbye!")


if __name__ == "__main__":
    main()
