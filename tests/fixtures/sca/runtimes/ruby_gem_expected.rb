require 'yaml'; require 'json'; require 'rubygems'
dir = ARGV[0]
rels = YAML.load_file(File.join(dir, 'releases.yml')).map { |r| r['version'].to_s }.select { |v| v =~ /\A\d+\.\d+\.\d+\z/ }
out = {}
Dir[File.join(dir, 'advisories', '*.yml')].sort.each do |f|
  a = YAML.load_file(f)
  reqs = (a['patched_versions'] || []) + (a['unaffected_versions'] || [])
  id = a['cve'] ? "CVE-#{a['cve']}" : "GHSA-#{a['ghsa']}"
  out[id] = rels.reject { |v| reqs.any? { |r| Gem::Requirement.new(*r.split(', ')).satisfied_by?(Gem::Version.new(v)) } }
end
puts JSON.generate(out)
