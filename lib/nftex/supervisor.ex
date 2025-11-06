defmodule NFTex.Supervisor do
  @moduledoc """
  Supervisor for the NFTex JSON port process.

  This supervisor ensures the JSON port process is restarted if it crashes,
  providing fault tolerance for the nftables interface.

  ## Usage

      children = [
        {NFTex.Supervisor, name: NFTex}
      ]

      Supervisor.start_link(children, strategy: :one_for_one)

  Then you can use the registered name:

      NFTex.Table.create(NFTex, %{name: "filter", family: :inet})
  """

  use Supervisor

  @spec start_link(keyword()) :: Supervisor.on_start()
  def start_link(opts \\ []) do
    Supervisor.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(opts) do
    port_name = opts[:name] || NFTex

    children = [
      {NFTex.JSONPort, [name: port_name]}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end
