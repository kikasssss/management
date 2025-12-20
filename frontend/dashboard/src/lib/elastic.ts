export interface ElasticSearchResponse<T> {
  hits: {
    hits: Array<{
      _id: string;
      _source: T;
    }>;
  };
}

export class ElasticClient {
  private baseURL: string;

  constructor() {
    this.baseURL = process.env.ELASTIC_URL ?? "http://localhost:9200";
  }

  private getHeaders(): HeadersInit {
    return {
      "Content-Type": "application/json",
    };
  }

  // ---------- SEARCH ----------
  async search<T>(
    index: string,
    queryBody: Record<string, unknown>
  ): Promise<Array<{ _id: string; _source: T }>> {
    const url = `${this.baseURL}/${index}/_search`;

    const res = await fetch(url, {
      method: "POST",
      headers: this.getHeaders(),
      body: JSON.stringify(queryBody),
    });

    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Elastic Search Error: ${err}`);
    }

    const data: ElasticSearchResponse<T> = await res.json();
    return data.hits?.hits ?? [];
  }

  // ---------- GET DOCUMENT ----------
  async getDocument<T>(
    index: string,
    id: string
  ): Promise<{ _id: string; _source: T }> {
    const url = `${this.baseURL}/${index}/_doc/${id}`;

    const res = await fetch(url, {
      method: "GET",
      headers: this.getHeaders(),
    });

    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Elastic Get Error: ${err}`);
    }

    return (await res.json()) as { _id: string; _source: T };
  }

  // ---------- INDEX DOCUMENT ----------
  async indexDocument<T>(
    index: string,
    body: T
  ): Promise<{ result: string; _id: string }> {
    const url = `${this.baseURL}/${index}/_doc`;

    const res = await fetch(url, {
      method: "POST",
      headers: this.getHeaders(),
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Elastic Index Error: ${err}`);
    }

    return (await res.json()) as { result: string; _id: string };
  }
}

export const elastic = new ElasticClient();
