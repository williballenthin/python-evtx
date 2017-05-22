#!/usr/bin/python
#    This file is part of python-evtx.
#
#   Copyright 2012, 2013 Willi Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
import six

import Evtx.Nodes as e_nodes
import xml.sax.saxutils


XML_HEADER = "<?xml version=\"1.1\" encoding=\"utf-8\" standalone=\"yes\" ?>\n"


class UnexpectedElementException(Exception):
    def __init__(self, msg):
        super(UnexpectedElementException, self).__init__(msg)


def to_xml_string(s):
    s = xml.sax.saxutils.escape(s, {'"': '&quot;'})
    return s


def render_root_node(root_node, subs):
    """
    render the given root node using the given substitutions into XML.

    Args:
      root_node (e_nodes.RootNode): the node to render.
      subs (list[str]): the substitutions that maybe included in the XML.

    Returns:
      str: the rendered XML document.
    """
    def rec(node, acc):
        if isinstance(node, e_nodes.EndOfStreamNode):
            pass  # intended
        elif isinstance(node, e_nodes.OpenStartElementNode):
            acc.append("<")
            acc.append(node.tag_name())
            for child in node.children():
                if isinstance(child, e_nodes.AttributeNode):
                    acc.append(" ")
                    acc.append(to_xml_string(child.attribute_name().string()))
                    acc.append("=\"")
                    rec(child.attribute_value(), acc)
                    acc.append("\"")
            acc.append(">")
            for child in node.children():
                rec(child, acc)
            acc.append("</")
            acc.append(to_xml_string(node.tag_name()))
            acc.append(">\n")
        elif isinstance(node, e_nodes.CloseStartElementNode):
            pass  # intended
        elif isinstance(node, e_nodes.CloseEmptyElementNode):
            pass  # intended
        elif isinstance(node, e_nodes.CloseElementNode):
            pass  # intended
        elif isinstance(node, e_nodes.ValueNode):
            acc.append(to_xml_string(node.children()[0].string()))
        elif isinstance(node, e_nodes.AttributeNode):
            pass  # intended
        elif isinstance(node, e_nodes.CDataSectionNode):
            acc.append("<![CDATA[")
            acc.append(to_xml_string(node.cdata()))
            acc.append("]]>")
        elif isinstance(node, e_nodes.EntityReferenceNode):
            acc.append(to_xml_string(node.entity_reference()))
        elif isinstance(node, e_nodes.ProcessingInstructionTargetNode):
            acc.append(to_xml_string(node.processing_instruction_target()))
        elif isinstance(node, e_nodes.ProcessingInstructionDataNode):
            acc.append(to_xml_string(node.string()))
        elif isinstance(node, e_nodes.TemplateInstanceNode):
            raise UnexpectedElementException("TemplateInstanceNode")
        elif isinstance(node, e_nodes.NormalSubstitutionNode):
            acc.append(subs[node.index()])
        elif isinstance(node, e_nodes.ConditionalSubstitutionNode):
            acc.append(subs[node.index()])
        elif isinstance(node, e_nodes.StreamStartNode):
            pass  # intended

    acc = []
    for c in root_node.template().children():
        rec(c, acc)
    return "".join(acc)


def evtx_record_xml_view(record, cache=None):
    '''
    render the given record into an XML document.

    Args:
      record (Evtx.Record): the record to render.

    Returns:
      str: the rendered XML document.
    '''
    def rec(root_node):
        subs = []
        for sub in root_node.substitutions():
            if isinstance(sub, six.string_types):
                raise RuntimeError('string sub?')

            if sub is None:
                raise RuntimeError('null sub?')

            if isinstance(sub, e_nodes.BXmlTypeNode):
                subs.append(rec(sub.root()))
            else:
                subs.append(sub.string())

        return render_root_node(root_node, subs)

    return rec(record.root())


def evtx_chunk_xml_view(chunk):
    """
    Generate XML representations of the records in an EVTX chunk.

    Does not include the XML <?xml... header.
    Records are ordered by chunk.records()

    Args:
      chunk (Evtx.Chunk): the chunk to render.

    Yields:
      tuple[str, Evtx.Record]: the rendered XML document and the raw record.
    """
    for record in chunk.records():
        record_str = evtx_record_xml_view(record)
        yield record_str, record


def evtx_file_xml_view(file_header):
    """
    Generate XML representations of the records in an EVTX file.

    Does not include the XML <?xml... header.
    Records are ordered by file_header.chunks(), and then by chunk.records()

    Args:
      chunk (Evtx.FileHeader): the file header to render.

    Yields:
      tuple[str, Evtx.Record]: the rendered XML document and the raw record.
    """
    for chunk in file_header.chunks():
        for record in chunk.records():
            record_str = evtx_record_xml_view(record)
            yield record_str, record


def evtx_template_readable_view(root_node, cache=None):
    def rec(node, acc):
        if isinstance(node, e_nodes.EndOfStreamNode):
            pass  # intended
        elif isinstance(node, e_nodes.OpenStartElementNode):
            acc.append("<")
            acc.append(node.tag_name())
            for child in node.children():
                if isinstance(child, e_nodes.AttributeNode):
                    acc.append(" ")
                    acc.append(child.attribute_name().string())
                    acc.append("=\"")
                    rec(child.attribute_value(), acc)
                    acc.append("\"")
            acc.append(">")
            for child in node.children():
                rec(child, acc)
            acc.append("</")
            acc.append(node.tag_name())
            acc.append(">\n")
        elif isinstance(node, e_nodes.CloseStartElementNode):
            pass  # intended
        elif isinstance(node, e_nodes.CloseEmptyElementNode):
            pass  # intended
        elif isinstance(node, e_nodes.CloseElementNode):
            pass  # intended
        elif isinstance(node, e_nodes.ValueNode):
            acc.append(node.children()[0].string())
        elif isinstance(node, e_nodes.AttributeNode):
            pass  # intended
        elif isinstance(node, e_nodes.CDataSectionNode):
            acc.append("<![CDATA[")
            acc.append(node.cdata())
            acc.append("]]>")
        elif isinstance(node, e_nodes.EntityReferenceNode):
            acc.append(node.entity_reference())
        elif isinstance(node, e_nodes.ProcessingInstructionTargetNode):
            acc.append(node.processing_instruction_target())
        elif isinstance(node, e_nodes.ProcessingInstructionDataNode):
            acc.append(node.string())
        elif isinstance(node, e_nodes.TemplateInstanceNode):
            raise UnexpectedElementException("TemplateInstanceNode")
        elif isinstance(node, e_nodes.NormalSubstitutionNode):
            acc.append("[Normal Substitution(index={}, type={})]".format(
                node.index(), node.type()))
        elif isinstance(node, e_nodes.ConditionalSubstitutionNode):
            acc.append("[Conditional Substitution(index={}, type={})]".format(
                node.index(), node.type()))
        elif isinstance(node, e_nodes.StreamStartNode):
            pass  # intended

    acc = []
    for c in root_node.template().children():
        rec(c, acc)
    return "".join(acc)
