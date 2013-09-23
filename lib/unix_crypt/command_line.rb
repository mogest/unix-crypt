require 'optparse'
require 'ostruct'
require 'io/console'

class UnixCrypt::CommandLine
  attr_reader :options

  def initialize(argv)
    @options = Opts.parse(argv)
  end

  def encrypt
    if @options.password.nil?
      @options.password = ask_password
    else
      password_warning
    end

    puts @options.hasher.build(@options.password, @options.salt, @options.rounds)
    clear_string(@options.password)
  end

  private
  class Opts
    HASHERS = {
      :SHA512 => UnixCrypt::SHA512,
      :SHA256 => UnixCrypt::SHA256,
      :MD5    => UnixCrypt::MD5
    }

    def self.parse(args)
      options            = OpenStruct.new
      options.hashmethod = :SHA512
      options.hasher     = HASHERS[options.hashmethod]
      options.password   = nil
      options.salt       = nil
      options.rounds     = nil
      options.leftovers  = OptionParser.new do |opts|
        opts.banner = "Usage: #{File.basename $0} [options]"
        opts.separator "Encrypts password using the unix-crypt gem"
        opts.separator ""
        opts.separator "Options:"

        opts.on("-h", "--hash [HASH]", String, "Set hash algorithm [SHA512 (default), SHA256, MD5]") do |hasher|
          options.hashmethod = hasher.to_s.upcase.to_sym
          options.hasher     = HASHERS[options.hashmethod]
          abort "Invalid hash algorithm for -h/--hash" if options.hasher.nil?
        end

        opts.on("-p", "--password [PASSWORD]", String, "Provide password on command line (insecure!)") do |password|
          abort "Invalid password for -p/--password" if password.nil?
          options.password = password
          $0 = $0 # this invocation will get rid of the command line arguments from the process list
        end

        opts.on("-s", "--salt [SALT]", String, "Provide hash salt") do |salt|
          abort "Invalid salt for -s/--salt" if salt.nil?
          options.salt = salt
        end

        opts.on("-r", "--rounds [ROUNDS]", Integer, "Set number of hashing rounds (SHA256/SHA512 only)") do |rounds|
          abort "Invalid hashing rounds for -r/--rounds" if rounds.nil? || rounds.to_i <= 0
          options.rounds = rounds
        end

        opts.on_tail("-h", "--help", "Show this message") do
          puts opts
          exit
        end

        opts.on_tail("-v", "--version", "Show version") do
          puts UnixCrypt::VERSION
          exit
        end
      end.parse!(args)
      options
    end
  end

  def ask_noecho(message)
    $stderr.print message
    result = $stdin.noecho(&:gets)
    $stderr.puts
    result
  end

  def password_warning
    $stderr.puts "warning: providing a password on the command line is insecure"
  end

  def clear_string(string)
    string.replace(" " * string.length)
  end

  def ask_password
    password = ask_noecho("Enter password: ")
    twice    = ask_noecho("Verify password: ")

    if password != twice
      clear_string(password)
      clear_string(twice)
      abort "Passwords don't match"
    end

    clear_string(twice)
    password.chomp!
  end
end