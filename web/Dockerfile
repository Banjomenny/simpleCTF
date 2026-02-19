FROM php:8.2-apache

# Install mysqli extension for MySQL connectivity
RUN docker-php-ext-install mysqli

COPY src/ /var/www/html/
RUN chown -R www-data:www-data /var/www/html


# Write the flag from the FLAG_FILE_UPLOAD env var at container start
# Flag lives outside the web root so it can only be read via code execution
CMD ["sh", "-c", "echo \"$FLAG_FILE_UPLOAD\" > /flag.txt && chmod 644 /flag.txt && exec apache2-foreground"]
