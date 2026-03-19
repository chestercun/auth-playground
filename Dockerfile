FROM python:3.12

WORKDIR /app

RUN pip install flask pyjwt requests

COPY oidc_sim.py .

CMD ["python", "oidc_sim.py"]
