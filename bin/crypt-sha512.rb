#!/usr/bin/env ruby

require 'optparse'
require 'ostruct'
require 'io/console'
require 'rubygems'
require File.expand_path('../../lib/unix_crypt', __FILE__)

class Opts
  def self.parse(args)
    options           = OpenStruct.new
    options.password  = nil
    options.leftovers = OptionParser.new do |opts|
      opts.banner = "Usage: #{File.basename __FILE__} [options]"
      opts.separator "Encrypts password using crypt-SHA512 for unix password file"
      opts.separator ""
      opts.separator "Options:"

      opts.on("-p", "--password [PASSWORD]", String, "Set password on command line (insecure!)") do |password|
        options.password = password
      end

      opts.on_tail("-h", "--help", "Show this message") do
        puts opts
        exit
      end

      opts.on_tail("-v", "--version", "Show version") do
        specfile = File.expand_path("../../unix-crypt.gemspec", __FILE__)
        spec = Gem::Specification::load(specfile)
        puts spec.version
        exit
      end
    end.parse!(args)
    options
  end
end

def ask_noecho(message)
  print message
  result = STDIN.noecho(&:gets)
  puts
  result
end

def ask_password
  password = ask_noecho("Enter password: ")
  twice    = ask_noecho("Verify password: ")
  abort "Passwords don't match" unless password == twice
  password.chomp # remove CR/LF
end

def generate_password(password)
  # Automatically generates salt using SecureRandom
  # Use 50K rounds instead of default 5K rounds
  UnixCrypt::SHA512.build(password, nil, 50_000)
end

if __FILE__ == $0
  options  = Opts.parse(ARGV)
  password = options.password
  password = ask_password if password.to_s.empty?
  puts generate_password(password)
end
