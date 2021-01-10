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

# Development
Pithus is currently in beta so if you want to contribute, please refer to the [Cookiecutter documentation](https://cookiecutter-django.readthedocs.io/en/latest/).

## SASS
To apply SASS file changes, just run the following command:
```
sassc bazaar/static/front/sass/project.scss backend/static/front/css/project.css
``` 
