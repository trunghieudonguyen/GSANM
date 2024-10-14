# FROM vulnerables/web-dvwa:latest

# USER root

# # Cập nhật sources list
# RUN sed -i 's/stretch/buster/g' /etc/apt/sources.list

# # Sao chép file cấu hình supervisord
# COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# # Sao chép script khởi động
# COPY start.sh /start.sh
# RUN chmod +x /start.sh

# # Chuyển hướng log Apache ra stdout và stderr
# RUN ln -sf /dev/stdout /var/log/apache2/access.log \
#     && ln -sf /dev/stderr /var/log/apache2/error.log

# # Sử dụng supervisord để quản lý các process
# CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
# Sử dụng DVWA image mới nhất
FROM vulnerables/web-dvwa:latest

# Chuyển sang quyền root để cài đặt và cấu hình
USER root

# Cập nhật sources list (nếu cần thiết)
RUN sed -i 's/stretch/buster/g' /etc/apt/sources.list

# Sao chép file cấu hình supervisord
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Chuyển hướng log Apache ra stdout và stderr
RUN ln -sf /dev/stdout /var/log/apache2/access.log \
    && ln -sf /dev/stderr /var/log/apache2/error.log

# Sử dụng supervisord để quản lý các process
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
