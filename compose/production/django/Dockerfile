
FROM python:3.8-slim-buster

ENV PYTHONUNBUFFERED 1

RUN apt-get update \
  # dependencies for building Python packages
  && apt-get install -y build-essential \
  # psycopg2 dependencies
  && apt-get install -y libpq-dev \
  # Translations dependencies
  && apt-get install -y gettext \
  # ssdeep dependencies
  && apt-get install -y libffi-dev python3 python3-dev python3-pip libfuzzy-dev git libcairo2 \
  # cleaning up unused files
  && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
  && rm -rf /var/lib/apt/lists/*

RUN addgroup --system django \
    && adduser --system --ingroup django django

# Requirements are installed here to ensure they will be cached.
COPY ./requirements /requirements
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r /requirements/production.txt \
    && rm -rf /requirements

# Install APKid
RUN pip install --upgrade wheel
RUN pip wheel --wheel-dir=/tmp/yara-python --build-option="build" --build-option="--enable-dex" git+https://github.com/VirusTotal/yara-python.git@v3.11.0
RUN pip install --no-index --find-links=/tmp/yara-python yara-python
RUN pip install apkid

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
