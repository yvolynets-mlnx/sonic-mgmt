FROM python:2.7-jessie

ADD ./start.sh /root/
# https://github.com/moby/moby/issues/2745
#ADD ../../helpers/pfc_gen.py /root/
ADD ./pfc_gen.py /root/

CMD ["/root/start.sh"]
