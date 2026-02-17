
FROM python:3.13.10-trixie

ENV PYTHONUNBUFFERED 1

RUN apt-get update \
  # dependencies for building Python packages
  && apt-get install -y build-essential \
  # psycopg2 dependencies
  && apt-get install -y libpq-dev \
  # Translations dependencies
  && apt-get install -y gettext \
  # ssdeep dependencies
  && apt-get install -y libffi-dev python3 python3-dev python3-pip libfuzzy-dev git libcairo2 graphviz\
  # cleaning up unused files
  && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
  && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /home/django 
RUN addgroup --system django \
    && adduser --system --ingroup django django --home /home/django
RUN chmod 775 /home/django && chown django:django /home/django

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

RUN pip install --no-cache-dir -r /requirements/production.txt \
    && rm -rf /requirements

# Install APKiD https://github.com/rednaga/APKiD/blob/master/Dockerfile
RUN git clone https://github.com/rednaga/APKiD.git && \
    cd APKiD && \
    git checkout 9abdce7c4fb0408ae9b00bd6cd25daaa96f57068 && \
    python prep-release.py && \
    python setup.py install && \
    cd .. && \
    rm -rf APKiD

COPY ./compose/production/django/entrypoint /entrypoint
RUN sed -i 's/\r$//g' /entrypoint
RUN chmod +x /entrypoint

COPY --chown=django:django ./compose/production/django/start /start
RUN sed -i 's/\r$//g' /start
RUN chmod +x /start
COPY --chown=django:django . /app

COPY --chown=django:django ./compose/production/django/django-q/start /start-worker
RUN sed -i 's/\r$//g' /start-worker
RUN chmod +x /start-worker
RUN chown django /start-worker

USER django

WORKDIR /app

ENTRYPOINT ["/entrypoint"]
