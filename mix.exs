defmodule OIDC.MixProject do
  use Mix.Project

  def project do
    [
      app: :oidc,
      description: "Convenience functions to work with OpenID Connect",
      version: "0.3.2",
      elixir: "~> 1.12",
      elixirc_paths: elixirc_paths(Mix.env()),
      docs: [
        main: "readme",
        extras: ["README.md"]
      ],
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package(),
      source_url: "https://github.com/tanguilp/oidc"
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:dialyxir, "~> 1.1", only: :dev, runtime: false},
      {:ex_doc, "~> 0.25", only: :dev, runtime: false},
      {:hackney, "~> 1.17", optional: true},
      {:jason, "~> 1.2"},
      {:jwks_uri_updater, "~> 1.1"},
      {:oauth2_metadata_updater, "~> 1.2"},
      {:oauth2_utils, "~> 0.1.0"},
      {:tesla_oauth2_client_auth, "~> 1.0"}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  def package() do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/tanguilp/oidc"}
    ]
  end
end
