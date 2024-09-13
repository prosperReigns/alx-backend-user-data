#!/usr/bin/env python3
"""This module implements personal data security"""
import logging
import re
import os
from typing import List
import mysql.connector


# Define the PII_FIELDS constant
PII_FIELDS = ("name", "email", "phone", "ssn", "password")


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """Constructor method for RedactingFormatter class"""
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Formats the specified log record as text. Filters values in
        incoming log records using filter_datum."""
        message = record.getMessage()
        record.msg = filter_datum(self.fields,
                                  self.REDACTION, message, self.SEPARATOR)
        return super(RedactingFormatter, self).format(record)


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """This function returns the log message obfuscated"""
    for field in fields:
        pattern = f"{field}=.*?{separator}"
        message = re.sub(pattern, f"{field}={redaction}{separator}", message)
    return message


def get_logger() -> logging.Logger:
    """Creates a logger that obfuscates PII fields"""
    # Create a logger with the name "user_data"
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    # Create a StreamHandler
    stream_handler = logging.StreamHandler()

    # Create and set the formatter to the handler
    formatter = RedactingFormatter(PII_FIELDS)
    stream_handler.setFormatter(formatter)

    # Add the handler to the logger
    logger.addHandler(stream_handler)

    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """This function returns a connector to the database"""
    connection = mysql.connector.connect(
        host=os.getenv('PERSONAL_DATA_DB_HOST', 'localhost'),
        database=os.getenv('PERSONAL_DATA_DB_NAME'),
        user=os.getenv('PERSONAL_DATA_DB_USERNAME', 'root'),
        password=os.getenv('PERSONAL_DATA_DB_PASSWORD', '')
    )
    return connection


def main():
    """This function obtains a database connection using get_db and retrieve
    all rows in the users table and display each row in a filtered format"""
    logger = get_logger()
    connection = get_db()
    cursor = connection.cursor()
    cursor.execute("select * from users;")
    column_names = [desc[0] for desc in cursor.description]
    for row in cursor:
        row_info = "; ".join(f"{desc}={value}" for desc, value in zip(column_names, row))
        logger.info(row_info)
    cursor.close()
    connection.close()


if __name__ == '__main__':
    main()
