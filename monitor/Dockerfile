# ruwa soak monitor — zero-dependency Python service.
FROM python:3.12-slim
WORKDIR /app
COPY monitor.py .
# Railway sets $PORT; the monitor binds it for the dashboard + webhook receiver.
ENV PORT=8090
EXPOSE 8090
CMD ["python", "monitor.py"]
