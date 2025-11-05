defmodule NFTex.Kernel.Netlink do
  @moduledoc """
  Low-level netlink operations for communicating with the kernel.

  This module provides functions for:
  - Opening and closing netlink sockets
  - Sending batched messages to the kernel
  - Receiving responses from the kernel
  - Parsing netlink error messages

  ## Workflow

  1. Open a netlink socket
  2. Create and populate a batch
  3. Send the batch via netlink
  4. Receive response from kernel
  5. Parse any errors
  6. Close the socket

  ## Example

      # Open netlink socket
      {:ok, socket_id} = NFTex.Kernel.Netlink.socket_open(pid)

      # Create a batch (see NFTex.Kernel.Batch)
      {:ok, batch_id} = NFTex.Kernel.Batch.alloc(pid)

      # Build and add nftables messages to the batch...
      # (using table, chain, rule operations)

      # Send batch to kernel
      {:ok, bytes_sent} = NFTex.Kernel.Netlink.send_batch(pid, socket_id, batch_id)

      # Receive response
      {:ok, response_data} = NFTex.Kernel.Netlink.recv(pid, socket_id, 8192)

      # Parse any errors
      case NFTex.Kernel.Netlink.parse_error(pid, response_data) do
        :ok -> :success
        {:error, reason} -> {:error, reason}
      end

      # Clean up
      :ok = NFTex.Kernel.Netlink.socket_close(pid, socket_id)
      :ok = NFTex.Kernel.Batch.free(pid, batch_id)
  """

  alias NFTex.Port

  @type resource_id :: non_neg_integer()
  @type socket_id :: resource_id()
  @type batch_id :: resource_id()

  @doc """
  Opens a netlink socket for NETLINK_NETFILTER communication.

  Returns `{:ok, socket_id}` on success or `{:error, reason}` on failure.

  The socket must be closed when done using `socket_close/2`.

  ## Example

      {:ok, socket_id} = NFTex.Kernel.Netlink.socket_open(pid)
      # ... use socket ...
      :ok = NFTex.Kernel.Netlink.socket_close(pid, socket_id)
  """
  @spec socket_open(pid()) :: {:ok, socket_id()} | {:error, term()}
  def socket_open(pid) do
    Port.call(pid, {:nl_socket_open})
  end

  @doc """
  Closes a netlink socket.

  ## Parameters

  - `pid` - Port process ID
  - `socket_id` - Socket resource ID from `socket_open/1`

  Returns `:ok` on success or `{:error, reason}` on failure.
  """
  @spec socket_close(pid(), socket_id()) :: :ok | {:error, term()}
  def socket_close(pid, socket_id) do
    Port.call(pid, {:nl_socket_close, socket_id})
  end

  @doc """
  Sends a batch of netlink messages to the kernel.

  ## Parameters

  - `pid` - Port process ID
  - `socket_id` - Socket resource ID from `socket_open/1`
  - `batch_id` - Batch resource ID from `NFTex.Kernel.Batch.alloc/3`

  Returns `{:ok, bytes_sent}` on success or `{:error, reason}` on failure.

  ## Example

      {:ok, socket_id} = NFTex.Kernel.Netlink.socket_open(pid)
      {:ok, batch_id} = NFTex.Kernel.Batch.alloc(pid)

      # Build batch with nftables operations...

      {:ok, bytes_sent} = NFTex.Kernel.Netlink.send_batch(pid, socket_id, batch_id)
  """
  @spec send_batch(pid(), socket_id(), batch_id()) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def send_batch(pid, socket_id, batch_id) do
    Port.call(pid, {:nl_send_batch, socket_id, batch_id})
  end

  @doc """
  Receives data from a netlink socket.

  ## Parameters

  - `pid` - Port process ID
  - `socket_id` - Socket resource ID from `socket_open/1`
  - `buffer_size` - Size of receive buffer in bytes (default: 8192)

  Returns `{:ok, binary_data}` containing the received message or `{:error, reason}`.

  The buffer size should be large enough to hold the expected response. Common sizes:
  - 8192 bytes for typical responses
  - 32768 bytes for larger responses (e.g., table dumps)

  ## Example

      {:ok, socket_id} = NFTex.Kernel.Netlink.socket_open(pid)
      {:ok, bytes_sent} = NFTex.Kernel.Netlink.send_batch(pid, socket_id, batch_id)

      # Receive response
      {:ok, response} = NFTex.Kernel.Netlink.recv(pid, socket_id, 8192)
  """
  @spec recv(pid(), socket_id(), non_neg_integer()) :: {:ok, binary()} | {:error, term()}
  def recv(pid, socket_id, buffer_size \\ 8192) do
    Port.call(pid, {:nl_recv, socket_id, buffer_size})
  end

  @doc """
  Parses a netlink message for errors.

  ## Parameters

  - `pid` - Port process ID
  - `binary_data` - Binary data received from `recv/3`

  Returns:
  - `:ok` if the message is a success ACK or not an error message
  - `{:error, reason}` if the message contains an error with a human-readable description

  ## Example

      {:ok, response} = NFTex.Kernel.Netlink.recv(pid, socket_id, 8192)

      case NFTex.Kernel.Netlink.parse_error(pid, response) do
        :ok ->
          IO.puts("Operation successful")

        {:error, reason} ->
          IO.puts("Kernel error: \#{reason}")
      end

  ## Error Messages

  The error parser maps errno values to human-readable messages like:
  - "Permission denied (EACCES)"
  - "Invalid argument (EINVAL)"
  - "File exists (EEXIST)"
  - And many more...
  """
  @spec parse_error(pid(), binary()) :: :ok | {:error, String.t()}
  def parse_error(pid, binary_data) when is_binary(binary_data) do
    Port.call(pid, {:nl_parse_error, binary_data})
  end

  @doc """
  Helper function that sends a batch and handles the response with error parsing.

  This is a convenience function that combines `send_batch/3`, `recv/3`, and `parse_error/2`.

  ## Parameters

  - `pid` - Port process ID
  - `socket_id` - Socket resource ID from `socket_open/1`
  - `batch_id` - Batch resource ID from `NFTex.Kernel.Batch.alloc/3`
  - `buffer_size` - Size of receive buffer in bytes (default: 8192)

  Returns:
  - `{:ok, bytes_sent}` if successful
  - `{:error, reason}` if sending failed, receiving failed, or kernel returned an error

  ## Example

      {:ok, socket_id} = NFTex.Kernel.Netlink.socket_open(pid)
      {:ok, batch_id} = NFTex.Kernel.Batch.alloc(pid)

      # Build batch...

      case NFTex.Kernel.Netlink.send_and_receive(pid, socket_id, batch_id) do
        {:ok, bytes_sent} ->
          IO.puts("Successfully sent \#{bytes_sent} bytes to kernel")

        {:error, reason} ->
          IO.puts("Failed: \#{reason}")
      end
  """
  @spec send_and_receive(pid(), socket_id(), batch_id(), non_neg_integer()) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def send_and_receive(pid, socket_id, batch_id, buffer_size \\ 8192) do
    with {:ok, bytes_sent} <- send_batch(pid, socket_id, batch_id),
         {:ok, response} <- recv(pid, socket_id, buffer_size),
         :ok <- parse_error(pid, response) do
      {:ok, bytes_sent}
    end
  end
end
