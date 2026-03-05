FROM php:8.2-apache

# Abilita moduli Apache necessari
RUN a2enmod rewrite headers

# Installa estensioni PHP
RUN docker-php-ext-install pdo pdo_mysql

# Configura Apache per guardare solo public/
ENV APACHE_DOCUMENT_ROOT /var/www/html/public
RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf
RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf

# Crea struttura cartelle storage
RUN mkdir -p /var/www/html/storage/uploads/audio \
             /var/www/html/storage/uploads/lyrics \
             /var/www/html/storage/logs

# Imposta permessi corretti
RUN chown -R www-data:www-data /var/www/html/storage
RUN chmod -R 755 /var/www/html/storage/uploads
RUN chmod 750 /var/www/html/storage/logs

# ============================================
# CONFIGURAZIONE PHP - LIMITI UPLOAD
# ============================================
RUN { \
    echo 'expose_php = Off'; \
    echo 'upload_max_filesize = 12M'; \
    echo 'post_max_size = 15M'; \
    echo 'max_file_uploads = 5'; \
    echo 'memory_limit = 128M'; \
    echo 'max_execution_time = 60'; \
} > /usr/local/etc/php/conf.d/uploads.ini