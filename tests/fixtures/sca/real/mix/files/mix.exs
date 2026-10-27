defmodule Fixture.MixProject do
  use Mix.Project

  def project do
    [app: :fixture, version: "0.1.0", elixir: "~> 1.14", deps: deps()]
  end

  def application, do: [extra_applications: [:logger]]

  defp deps do
    [
      {:jason, "~> 1.4"},
      {:plug_cowboy, "~> 2.6"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false}
    ]
  end
end
