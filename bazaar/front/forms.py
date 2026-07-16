import logging
from django import forms

from bazaar.core.services import SearchService
from bazaar.core.utils import compute_genetic_analysis, transform_hl_results
from bazaar.front.utils import append_dexofuzzy_similarity, get_aggregations

from django.forms import ModelForm
from bazaar.core.models import Yara


class SimilaritySearchForm(forms.Form):
    hash = forms.CharField(max_length=128)
    algorithm = forms.ChoiceField(
        choices=[('ssdeep', 'ssdeep'), ('dexofuzzy', 'dexofuzzy'), ('func_hash', 'func_hash')])

    def do_search(self, sha=''):
        algorithm = self.cleaned_data['algorithm']
        hash = self.cleaned_data['hash'].strip()

        return SearchService.similarity_search(hash, algorithm, ignore_sha=sha)


class SearchForm(forms.Form):
    q = forms.CharField(max_length=128)

    def do_search(self):
        q = self.cleaned_data['q']

        try:
            raw_results = SearchService.search(q)
            results = transform_hl_results(raw_results)
            results = append_dexofuzzy_similarity(results, 'sim', 30)

            genetic_analysis = compute_genetic_analysis(results)
            return results, get_aggregations(raw_results), genetic_analysis
        except Exception as e:
            logging.error(e)
            return [], [], None


class BasicUploadForm(forms.Form):
    apk = forms.FileField()


class BasicUrlDownloadForm(forms.Form):
    url = forms.URLField()


class YaraCreateForm(ModelForm):
    class Meta:
        model = Yara
        fields = ['title', 'content', 'is_private']
