# frozen_string_literal: true

require_relative "lib/jwt_guard/version"

Gem::Specification.new do |spec|
  spec.name = "jwt_guard"
  spec.version = JWTGuard::VERSION
  spec.authors = ["Pranjal Kushwaha"]
  spec.email = ["pranjal0819@gmail.com"]

  spec.summary = "Simple and Secure JWT Authentication for Ruby Applications"
  spec.description = "is a secure, configurable gem for adding JWT authentication to Ruby applications, featuring " \
                     "RSA-based signature verification and seamless middleware integration. Ideal for APIs, " \
                     "it offers easy setup with environment-based customization and robust error handling."

  spec.homepage = "https://github.com/wollfish/jwt-guard"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.0.0"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .github appveyor Gemfile])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "jwt"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
  spec.metadata["rubygems_mfa_required"] = "true"
end
