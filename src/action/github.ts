// Minimal GitHub REST client for the Action: the few pull-request endpoints it needs, over fetch, with the token the
// runner provides. No SDK dependency; the base URL comes from GITHUB_API_URL so GitHub Enterprise Server works too.

export class GitHubError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

export interface PullFile {
  filename: string;
  status: string;
  /** The unified diff; absent for binary or very large files. */
  patch?: string;
}

export interface Comment {
  id: number;
  body: string;
}

/** A review comment on one line of the head commit, or on the whole file (`line` omitted). */
export interface ReviewComment {
  path: string;
  line?: number;
  body: string;
}

export class GitHub {
  constructor(
    private readonly token: string,
    private readonly repo: string,
    private readonly api = "https://api.github.com",
  ) {}

  private async request<T>(method: string, route: string, body?: unknown): Promise<T> {
    const res = await fetch(`${this.api}/repos/${this.repo}${route}`, {
      method,
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${this.token}`,
        "x-github-api-version": "2022-11-28",
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new GitHubError(`${method} ${route} → ${res.status} ${text.slice(0, 300)}`, res.status);
    }
    return (res.status === 204 ? undefined : await res.json()) as T;
  }

  /** Every page of a list endpoint (100 per page, at most `max` items). */
  private async all<T>(route: string, max = 3000): Promise<T[]> {
    const out: T[] = [];
    for (let page = 1; out.length < max; page++) {
      const items = await this.request<T[]>("GET", `${route}${route.includes("?") ? "&" : "?"}per_page=100&page=${page}`);
      out.push(...items);
      if (items.length < 100) break;
    }
    return out;
  }

  pullFiles(pr: number): Promise<PullFile[]> {
    return this.all(`/pulls/${pr}/files`);
  }

  reviewComments(pr: number): Promise<Comment[]> {
    return this.all(`/pulls/${pr}/comments`);
  }

  issueComments(pr: number): Promise<Comment[]> {
    return this.all(`/issues/${pr}/comments`);
  }

  postReviewComment(pr: number, commitId: string, c: ReviewComment): Promise<Comment> {
    const where = c.line === undefined ? { subject_type: "file" } : { line: c.line, side: "RIGHT" };
    return this.request("POST", `/pulls/${pr}/comments`, { body: c.body, commit_id: commitId, path: c.path, ...where });
  }

  postIssueComment(pr: number, body: string): Promise<Comment> {
    return this.request("POST", `/issues/${pr}/comments`, { body });
  }

  updateIssueComment(id: number, body: string): Promise<Comment> {
    return this.request("PATCH", `/issues/comments/${id}`, { body });
  }
}
