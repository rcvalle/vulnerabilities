#!/usr/bin/env ruby
# Copyright 2018 Ramon de C Valle
# SPDX-License-Identifier: 0BSD

require 'nokogiri'
require 'optparse'
require 'time'
require 'xmlsimple'
require 'yaml'

Version = [0, 0, 1]
Release = nil

titles = []

options = {}

OptionParser.new do |parser|
  parser.banner = "Usage: #{parser.program_name} [options] allitems-cvrf.xml"

  parser.separator('')
  parser.separator('Options:')

  parser.on('-h', '--help', 'Show this message') do
    puts parser
    exit
  end

  parser.on('--list x,y,z', Array, 'Specify the list of CVE identifiers') do |list|
    titles += list
  end

  parser.on('--list-file FILE', 'Specify the list of CVE identifiers') do |file|
    titles += File.readlines(file)
    titles.map!(&:strip)
  end

  parser.on('-o', '--output FILE', 'Output file') do |file|
    options[:file] = File.new(file, 'w+b')
  end

  parser.on('-v', '--verbose', 'Verbose mode') do |v|
    options[:verbose] = v
  end

  parser.on('--version', 'Show version') do
    puts parser.ver
    exit
  end
end.parse!

file = options[:file] || nil

vulnerabilities = []

reader = Nokogiri::XML::Reader(File.new(ARGV[0]))
reader.each do |node|
  next unless node.name == 'Vulnerability' && node.node_type == Nokogiri::XML::Reader::TYPE_ELEMENT
  vulnerability = XmlSimple.xml_in(node.outer_xml)
  next unless titles.empty? || titles.include?(vulnerability['Title'][0])
  vulnerabilities << {}
  vulnerabilities[-1]['description'] = nil
  vulnerabilities[-1]['name'] = vulnerability['Title'][0]
  vulnerabilities[-1]['published'] = nil
  vulnerabilities[-1]['updated'] = nil
  vulnerability['Notes'][0]['Note'].each do |note|
    case note['Type']
    when 'Description'
      vulnerabilities[-1]['description'] = note['content'].gsub(/\n/, ' ').gsub(/\s+/, ' ').strip
    when 'Other'
      case note['Title']
      when 'Published'
        vulnerabilities[-1]['published'] = Time.parse("#{note['content']} 00:00:00.000000000 Z")
      when 'Modified'
        vulnerabilities[-1]['updated'] = Time.parse("#{note['content']} 00:00:00.000000000 Z")
      end
    end
  end
end

vulnerabilities.reverse!

if file
  file.write(vulnerabilities.to_yaml)
  file.close
else
  puts vulnerabilities.to_yaml
end
