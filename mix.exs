defmodule Tenbin.DNS.MixProject do
  use Mix.Project

  @version "0.7.0"

  def project do
    [
      app: :tenbin_dns,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),

      # Test coverage configuration
      test_coverage: [summary: [threshold: 80]],

      # Documentation
      name: "Tenbin.DNS",
      description: "DNS packet parsing and creation library for Elixir",
      source_url: "https://github.com/smkwlab/tenbin_dns",
      homepage_url: "https://github.com/smkwlab/tenbin_dns",
      docs: docs(),
      package: package()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:credo, "~> 1.7.12", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4.1", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.38", only: :dev, runtime: false},
      {:inch_ex, github: "rrrene/inch_ex", only: [:dev, :test]},
      {:benchee, "~> 1.0", only: [:dev, :test]}
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
    ]
  end

  # Documentation configuration
  defp docs do
    [
      main: "Tenbin.DNS",
      name: "Tenbin.DNS",
      source_ref: "v#{@version}",
      source_url: "https://github.com/smkwlab/tenbin_dns",
      extras: [
        "README.md",
        "docs/EDNS_NAMING_CONVENTION.md"
      ],
      groups_for_extras: [
        "Guides": ~r/docs\/.*/
      ],
      groups_for_modules: [
        "Core": [Tenbin.DNS, DNSpacket, DNS]
      ],
      authors: ["Toshihiko SHIMOKAWA"]
    ]
  end

  # Package configuration for Hex
  defp package do
    [
      description: "DNS packet parsing and creation library with EDNS hybrid structure",
      files: ~w(lib .formatter.exs mix.exs README.md LICENSE docs/EDNS_NAMING_CONVENTION.md),
      licenses: ["MIT"],
      links: %{
        "GitHub" => "https://github.com/smkwlab/tenbin_dns",
        "Documentation" => "https://hexdocs.pm/tenbin_dns"
      },
      maintainers: ["Toshihiko SHIMOKAWA"]
    ]
  end
end
