FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY __init__.py partner_app.py echo_partner.py hostile_partner.py /app/demo/outside_agents/
RUN touch /app/demo/__init__.py

ENV PYTHONPATH=/app
ENV PORT=8080

EXPOSE 8080

CMD ["sh", "-c", "uvicorn demo.outside_agents.partner_app:create_deploy_app --factory --host 0.0.0.0 --port ${PORT:-8080}"]
