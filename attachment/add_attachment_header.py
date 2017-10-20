# -*- coding: utf-8 -*-
import logging

from fuglu.shared import ScannerPlugin, DUNNO,string_to_actioncode,apply_template


class AttachmentAddHeader(ScannerPlugin):
    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)
        self.logger = logging.getLogger('fuglu.plugin.DomainAction')

        self.requiredvars = {
             'blockedaddheader': {
                'default': '0',
                'description': 'if set to non zero value a header will be added for blocked files and the message will be accepted\n1:\tonly filename appended as header\n2:\tfilename and details will be added as header\nany other string value will be added as-it-is to header',
            }
        }

    def examine(self, suspect):
        urls = suspect.get_tag('block.file', defaultvalue=[])
        add_links = self.config.getboolean(self.section, 'blockedaddheader')
        if len(urls) == 0 or add_links == '0':
            return DUNNO
        elif add_links == '1':
            suspect.add_header('X-Fuglu-Block', str(urls['ascirep']), immediate=True)
        elif add_links == '2':
            suspect.add_header('X-Fuglu-Block', str(urls['content']), immediate=True)
        else:
            suspect.add_header('X-Fuglu-Block', str(add_links), immediate=True)
        return DUNNO
#        return string_to_actioncode(self.config.get('URIExtractPlugin', 'action'), self.config), apply_template(
#            self.config.get('URIExtractPlugin', 'message'), suspect, dict(domain=urls[0], blacklist='tbd'))