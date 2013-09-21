#!/usr/bin/env ruby

require 'optparse'
require 'ostruct'
require 'io/console'
require 'rubygems'
require File.expand_path('../../lib/unix_crypt', __FILE__)

class Opts

  HASHERS = {
    :SHA512 => Proc.new {|*args| UnixCrypt::SHA512.build(*args) },
    :SHA256 => Proc.new {|*args| UnixCrypt::SHA256.build(*args) },
    :MD5    => Proc.new {|*args| UnixCrypt::MD5.build(*args)    },
  }

  def self.parse(args)
    options            = OpenStruct.new
    options.hashmethod = :SHA512
    options.hasher     = HASHERS[options.hashmethod]
    options.password   = nil
    options.salt       = nil
    options.rounds     = nil
    options.leftovers  = OptionParser.new do |opts|
      opts.banner = "Usage: #{File.basename __FILE__} [options]"
      opts.separator "Encrypts password using crypt-SHA512 for unix password file"
      opts.separator ""
      opts.separator "Options:"

      opts.on("-h", "--hash [HASH]", String, "Set hash algorithm [default: SHA512; SHA256, MD5]") do |hasher|
        options.hashmethod = hasher.to_s.upcase.to_sym
        options.hasher     = HASHERS[options.hashmethod]
        abort "Invalid hash algorithm for -h/--hash" if options.hasher.nil?
      end

      opts.on("-p", "--password [PASSWORD]", String, "Provide password on command line (insecure!)") do |password|
        abort "Invalid password for -p/--password" if password.nil?
        options.password = password
      end

      opts.on("-s", "--salt [SALT]", String, "Provide hash salt") do |salt|
        abort "Invalid salt for -s/--salt" if salt.nil?
        options.salt = salt
      end

      opts.on("-r", "--rounds [ROUNDS]", Integer, "Set number of hashing rounds") do |rounds|
        abort "Invalid hashing rounds for -r/--rounds" if rounds.nil?
        options.rounds = rounds
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

def password_warning
  $stderr.puts <<-EOS

--> SECURITY WARNING <--
  Please emember to clear your shell history so that the
  password specified on the command-line is not retained!

EOS
end

def ask_password
  password = ask_noecho("Enter password: ")
  twice    = ask_noecho("Verify password: ")
  abort "Passwords don't match" unless password == twice
  password.chomp # remove CR/LF
end

def encrypt_password(argv)
  options  = Opts.parse(argv)
  if options.password.nil?
    options.password = ask_password
  else
    password_warning
  end

  #$stderr.puts "#{options.hashmethod}('#{options.password}', '#{options.salt}', #{options.rounds})"
  puts options.hasher.call(options.password, options.salt, options.rounds)
end

if __FILE__ == $0
  encrypt_password(ARGV)
end
