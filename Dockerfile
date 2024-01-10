FROM wiziocli.azurecr.io/wizcli:latest as wizcli
FROM python:3

WORKDIR action

# importing the action
COPY . /action
RUN pip install -r /action/requirements.txt

COPY --from=wizcli --chmod=777 /entrypoint /bin/wizcli

ENTRYPOINT [ "python3","/action/main.py" ]
