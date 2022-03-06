FROM python:3.8-slim-buster

ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

RUN apt-get update \
  # dependencies for building Python packages
  && apt-get install -y build-essential \
  # psycopg2 dependencies
  && apt-get install -y libpq-dev \
  # Translations dependencies
  && apt-get install -y gettext \
  # ssdeep dependencies
  && apt-get install -y libffi-dev python3 python3-dev python3-pip libfuzzy-dev git libcairo2 graphviz libjansson-dev \
  # adding tools to build yara
  && apt-get install -y curl sed autoconf autotools-dev automake libtool libmagic-dev pkg-config openssl \
  # cleaning up unused files
  && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
  && rm -rf /var/lib/apt/lists/*

# Requirements are installed here to ensure they will be cached.
COPY ./requirements /requirements
RUN pip install --upgrade pip
RUN pip install -r /requirements/local.txt


# # Install and recompile Yara to include androguard module
# RUN git clone https://github.com/VirusTotal/yara.git
# WORKDIR yara/libyara/modules/
# RUN curl -O https://raw.githubusercontent.com/Koodous/androguard-yara/master/androguard.c
# # FIXME sed works well on my machine but breaks in the docker, idk why
# # RUN sed -i -e 's/MODULE(cuckoo)/MODULE(cuckoo)'$'\\\nMODULE(androguard)/g' module_list
# RUN curl -O https://gist.githubusercontent.com/evilcel3ri/07b292a365c2e3d8f89bbb13ca0c940c/raw/d58cabb5a168b31c48608baef65ba2e8823bf679/gistfile1.txt | tee module_list
# WORKDIR ..
# # FIXME sed works well on my machine but breaks in the docker, idk why
# # RUN sed -i -e 's~MODULES += modules\/cuckoo.c~MODULES += modules\/cuckoo.c'$'\\\nMODULES += modules/androguard.c~g' Makefile.am
# RUN curl -O https://gist.githubusercontent.com/evilcel3ri/2da71c8e833885982428ea93c7c84258/raw/9790ff0945a618fdc036bf337bfda2055b0d5dc7/Makefile.am
# WORKDIR ..
# RUN ./bootstrap.sh
# RUN ./configure --enable-cuckoo --enable-dex
# RUN make
# RUN make install
# RUN echo "Done installing yara"
# WORKDIR /
# RUN git clone --recursive https://github.com/evilcel3ri/yara-python.git
# WORKDIR yara-python
# RUN python setup.py build
# RUN python setup.py install
RUN pip wheel --wheel-dir=yara-python-dex git+https://github.com/evilcel3ri/yara-python-dex.git
RUN pip install --no-index --find-links=yara-python-dex yara-python-dex

# Install APKiD https://github.com/rednaga/APKiD/blob/master/Dockerfile
RUN git clone https://github.com/evilcel3ri/APKiD.git && \
    cd APKiD && \
    git checkout f8720b7a371c31a694d45591af0b023f040febdd && \
    python prep-release.py && \
    python setup.py install && \
    cd .. && \
    rm -rf APKiD

COPY ./compose/production/django/entrypoint /entrypoint
RUN sed -i 's/\r$//g' /entrypoint
RUN chmod +x /entrypoint

COPY ./compose/local/django/start /start
RUN sed -i 's/\r$//g' /start
RUN chmod +x /start

COPY ./compose/local/django/django-q/start /start-worker
RUN sed -i 's/\r$//g' /start-worker
RUN chmod +x /start-worker

WORKDIR /app

ENTRYPOINT ["/entrypoint"]
