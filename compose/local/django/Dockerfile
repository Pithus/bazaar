FROM python:3.13.10-trixie

ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

RUN apt update \
  # dependencies for building Python packages
  && apt install -y build-essential \
  # psycopg2 dependencies
  && apt install -y libpq-dev \
  # Translations dependencies
  && apt install -y gettext \
  # ssdeep dependencies
  && apt install -y libffi-dev python3 python3-dev python3-pip libfuzzy-dev git libcairo2 graphviz\
  # cleaning up unused files
  && apt purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
  && rm -rf /var/lib/apt/lists/*

# Requirements are installed here to ensure they will be cached.
COPY ./requirements /requirements
RUN pip install --upgrade pip

# Special SSDEEP edge case
# AndroCFG requires ssdeep==3.4, but since setuptools dropped support of pkg_resources, install always fail
# This is a temporary fix until:
#   1) This PR gets merged https://github.com/DinoTools/python-ssdeep/pull/70
#   2) AndroCFG bumps ssdeep requirements to version 3.4.2 specified in above patch
RUN git clone https://github.com/DinoTools/python-ssdeep.git /python-ssdeep
COPY ./requirements/ssdeep.patch /python-ssdeep/ssdeep.patch
WORKDIR /python-ssdeep
RUN git apply ssdeep.patch
RUN python -m pip install /python-ssdeep
WORKDIR /

RUN pip install -r /requirements/local.txt 

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
