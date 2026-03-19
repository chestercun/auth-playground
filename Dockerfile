FROM python:3.12

WORKDIR /app

RUN pip install click cryptography flask pyjwt requests

COPY oidc_prod_lab.py .

CMD ["python", "oidc_prod_lab.py"]
