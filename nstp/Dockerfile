FROM python:3
RUN mkdir /solution
COPY client.py /solution/
COPY interpreter.py /solution/
COPY network.py /solution/
COPY pki.py /solution/
COPY nstp_v4_pb2.py /solution/
RUN pip3 install protobuf
RUN pip3 install pynacl
RUN pip3 install asyncio
RUN pip3 install pyduktape
RUN pip3 install click
RUN pip3 install Path
RUN pip3 install Any
RUN chmod +x /solution/client.py /solution/interpreter.py /solution/network.py /solution/pki.py /solution/nstp_v4_pb2.py 
WORKDIR /solution
ENTRYPOINT [ "python", "./client.py" ]