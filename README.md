<p align="center"><img src="https://raw.githubusercontent.com/Pithus/bazaar/master/bazaar/static/images/logo.png"></p>

[![Built with Cookiecutter Django](https://img.shields.io/badge/built%20with-Cookiecutter%20Django-ff69b4.svg)](https://github.com/pydanny/cookiecutter-django/)

# Pithus
Pithus is a free and open-source platform to analyze Android applications for activists, journalists, NGOs, researchers...

Analyses, which we want to be as comprehensive as possible, rely on multiple well-known tools such as:
* [APKiD](https://github.com/rednaga/APKiD)
* [ssdeep](https://github.com/DinoTools/python-ssdeep)
* [Dexofuzzy](https://github.com/ESTsecurity/Dexofuzzy)
* [Quark-Engine](https://github.com/quark-engine/quark-engine)
* [AndroGuard](https://github.com/androguard/androguard)
* [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
* [Exodus-core](https://github.com/Exodus-Privacy/exodus-core)

When an APK is submitted, it is analyzed by the different tools listed above. Each report is stored in [ElasticSearch](https://www.elastic.co/). Analysis steps are defined in [tasks.py](https://github.com/Pithus/bazaar/blob/master/bazaar/core/tasks.py) file. 

The beta version is available at [beta.pithus.org](https://beta.pithus.org/).

# Development environment setup

Pithus is currently in beta so if you want to contribute, please refer to the [Cookiecutter documentation](https://cookiecutter-django.readthedocs.io/en/latest/).

On Linux:

```sh
git clone git@github.com:Pithus/bazaar.git
cd bazaar
```
It is possible to run the entire development stack with [docker-compose](https://docs.docker.com/compose/install/):

```sh
docker-compose -f local.yml up
```

Then browse to [http://localhost:8001] and enjoy Pithus!

⚠️**Important**⚠️:

It is possible that you might have an error for a missing index while browsing to the address the first time. It is probable that Django hasn't been properly loaded. To fix that, add a blank line in any of the Django file, save it and refresh the page in the browser.

## Set up the internal Python interpreter with Visual Studio Code

It is possible to run the entire development environment in a Docker container. This will allow you to run on the same Python interpreter as anyone else contributing to this project. To do so with Visual Studio Code, follow these steps:

* Install the [Python](https://marketplace.visualstudio.com/items?itemName=ms-python.python) and the [Remote Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extensions.
* Open the command palette and look for the option: "Remote Containers: Attach to running container".
* Choose `bazaar_local_django`.
* VSCode will restart, and you will be presented with a new window of VSCode.
* Open the file explorer and open the folder `/app`, the code is there.
* You are all set up!

*Note*: By default, only your theme and the Remote Containers will be installed, you will need to install more extension in the Docker manually. However, your settings will be imported automatically.

More information on developping in a container in the Visual Studio Code [documentation](https://code.visualstudio.com/docs/remote/containers).

## SASS
To apply SASS file changes, just run the following command:
```
sassc bazaar/static/front/sass/project.scss backend/static/front/css/project.css
``` 
## Reindex after adding a new field
```python
from django.conf import settings
from elasticsearch import Elasticsearch
import json

es = Elasticsearch(settings.ELASTICSEARCH_HOSTS)
mapping = json.load(open('bazaar/es_mappings/apk_analysis.json'))
es.indices.put_mapping(index=settings.ELASTICSEARCH_APK_INDEX, body=mapping.get('mappings'))
```
# Community

Do you have questions? Do you want to chat with us? Come join us on our discord: [https://discord.gg/PgdKfp4VMQ](https://discord.gg/PgdKfp4VMQ)
