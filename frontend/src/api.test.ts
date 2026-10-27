import { describe, it, expect, vi, beforeEach } from 'vitest';
import { streamChat } from './api';

describe('streamChat SSE Parser', () => {
  let mockHandlers: any;

  beforeEach(() => {
    mockHandlers = {
      onMeta: vi.fn(),
      onDelta: vi.fn(),
      onError: vi.fn(),
      onDone: vi.fn(),
    };
    global.fetch = vi.fn();
  });

  const createMockStream = (chunks: Uint8Array[]) => {
    let index = 0;
    return new ReadableStream({
      pull(controller) {
        if (index < chunks.length) {
          controller.enqueue(chunks[index++]);
        } else {
          controller.close();
        }
      }
    });
  };

  it('handles a normal stream ending with done', async () => {
    const encoder = new TextEncoder();
    const chunks = [
      encoder.encode('event: meta\ndata: {"model":"test"}\n\n'),
      encoder.encode('event: delta\ndata: {"text":"hello"}\n\n'),
      encoder.encode('event: done\ndata: {}\n\n')
    ];
    
    (global.fetch as any).mockResolvedValue({
      ok: true,
      body: createMockStream(chunks)
    });

    await streamChat({ message: 'test', conversation_history: [], security_context: null }, mockHandlers);

    expect(mockHandlers.onMeta).toHaveBeenCalledWith({ model: 'test' });
    expect(mockHandlers.onDelta).toHaveBeenCalledWith('hello');
    expect(mockHandlers.onDone).toHaveBeenCalled();
    expect(mockHandlers.onError).not.toHaveBeenCalled();
  });

  it('handles a valid final delta event without a trailing blank line', async () => {
    const encoder = new TextEncoder();
    const chunks = [
      encoder.encode('event: delta\ndata: {"text":"final text"}') // Missing \n\n
    ];
    
    (global.fetch as any).mockResolvedValue({
      ok: true,
      body: createMockStream(chunks)
    });

    await streamChat({ message: 'test', conversation_history: [], security_context: null }, mockHandlers);

    expect(mockHandlers.onDelta).toHaveBeenCalledWith('final text');
    expect(mockHandlers.onError).toHaveBeenCalledWith('Stream ended prematurely without completion event.');
    expect(mockHandlers.onDone).toHaveBeenCalled();
  });

  it('handles a valid final error event without a trailing blank line', async () => {
    const encoder = new TextEncoder();
    const chunks = [
      encoder.encode('event: error\ndata: {"error":"something went wrong"}') // Missing \n\n
    ];
    
    (global.fetch as any).mockResolvedValue({
      ok: true,
      body: createMockStream(chunks)
    });

    await streamChat({ message: 'test', conversation_history: [], security_context: null }, mockHandlers);

    expect(mockHandlers.onError).toHaveBeenCalledWith('something went wrong');
    // Also expected the premature end error since no done event
    expect(mockHandlers.onError).toHaveBeenCalledWith('Stream ended prematurely without completion event.');
    expect(mockHandlers.onDone).toHaveBeenCalled();
  });

  it('handles EOF without a done event', async () => {
    const encoder = new TextEncoder();
    const chunks = [
      encoder.encode('event: delta\ndata: {"text":"some text"}\n\n')
    ];
    
    (global.fetch as any).mockResolvedValue({
      ok: true,
      body: createMockStream(chunks)
    });

    await streamChat({ message: 'test', conversation_history: [], security_context: null }, mockHandlers);

    expect(mockHandlers.onDelta).toHaveBeenCalledWith('some text');
    expect(mockHandlers.onError).toHaveBeenCalledWith('Stream ended prematurely without completion event.');
    expect(mockHandlers.onDone).toHaveBeenCalled();
  });

  it('handles a malformed or truncated final event without crashing', async () => {
    const encoder = new TextEncoder();
    const chunks = [
      encoder.encode('event: delta\ndata: {"text": "par') // JSON cutoff
    ];
    
    (global.fetch as any).mockResolvedValue({
      ok: true,
      body: createMockStream(chunks)
    });

    await streamChat({ message: 'test', conversation_history: [], security_context: null }, mockHandlers);

    // Should not crash. Shouldn't call onDelta because JSON is invalid.
    expect(mockHandlers.onDelta).not.toHaveBeenCalled();
    expect(mockHandlers.onError).toHaveBeenCalledWith('Stream ended prematurely without completion event.');
    expect(mockHandlers.onDone).toHaveBeenCalled();
  });

  it('handles split UTF-8 characters and multiple events arriving in a single read', async () => {
    // 🌍 is \xF0\x9F\x8C\x8D (4 bytes)
    const encoder = new TextEncoder();
    
    // Chunk 1: meta event + first delta with first 2 bytes of earth emoji
    const chunk1 = new Uint8Array([
      ...encoder.encode('event: meta\ndata: {"model":"test"}\n\n'),
      ...encoder.encode('event: delta\ndata: {"text":"'),
      0xF0, 0x9F // First two bytes of 🌍
    ]);

    // Chunk 2: remaining 2 bytes of earth emoji + end of JSON + done event
    const chunk2 = new Uint8Array([
      0x8C, 0x8D, // Last two bytes of 🌍
      ...encoder.encode('"}\n\nevent: done\ndata: {}\n\n')
    ]);

    (global.fetch as any).mockResolvedValue({
      ok: true,
      body: createMockStream([chunk1, chunk2])
    });

    await streamChat({ message: 'test', conversation_history: [], security_context: null }, mockHandlers);

    expect(mockHandlers.onMeta).toHaveBeenCalledWith({ model: 'test' });
    expect(mockHandlers.onDelta).toHaveBeenCalledWith('🌍');
    expect(mockHandlers.onDone).toHaveBeenCalled();
    expect(mockHandlers.onError).not.toHaveBeenCalled();
  });
});
