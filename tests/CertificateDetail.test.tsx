// @vitest-environment jsdom
import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent, cleanup } from '@testing-library/react';
import CertificateDetailPage from '../src/pages/CertificateDetail';
import { loadFixture } from './helpers';

const fixedNow = new Date(Date.UTC(2026, 6, 1, 12, 0, 0));

function parseInput(pem: string) {
  const textarea = screen.getByPlaceholderText(/BEGIN CERTIFICATE/);
  fireEvent.change(textarea, { target: { value: pem } });
  fireEvent.click(screen.getByRole('button', { name: /解析证书/ }));
}

function setEvalTime(value: string) {
  fireEvent.change(screen.getByTestId('eval-time'), { target: { value } });
}

beforeEach(() => {
  cleanup();
  localStorage.clear();
});

describe('CertificateDetailPage', () => {
  it('renders the key fields of a normal certificate (values from OpenSSL)', () => {
    render(<CertificateDetailPage now={fixedNow} />);
    parseInput(loadFixture('root-cert.pem'));

    expect(screen.getByTestId('cert-detail')).toBeInTheDocument();

    expect(screen.getByText('3F68365E414C779D9B7286C7DA55993F204ABCEC')).toBeInTheDocument();
    expect(screen.getAllByText('Test Root CA')).toHaveLength(2);
    expect(screen.getAllByText('TestOrg')).toHaveLength(2);
    expect(screen.getByText(/sha256WithRSAEncryption/)).toBeInTheDocument();
    expect(screen.getByText(/rsaEncryption/)).toBeInTheDocument();
    expect(screen.getByText('2048 bit')).toBeInTheDocument();
    expect(screen.getByText('TRUE')).toBeInTheDocument();
    expect(screen.getByText('有效')).toBeInTheDocument();
  });

  it('shows an expired badge and the expiry fields for an expired certificate', () => {
    render(<CertificateDetailPage now={fixedNow} />);
    parseInput(loadFixture('expired-cert.pem'));

    expect(screen.getByTestId('cert-detail')).toBeInTheDocument();
    expect(screen.getByText('0BADBEEFCAFEBABEDEADBEEFCAFEBABE')).toBeInTheDocument();
    expect(screen.getAllByText('expired.example.com')).toHaveLength(3);
    expect(screen.getByText('www.expired.example.com')).toBeInTheDocument();
    expect(screen.getByText('FALSE')).toBeInTheDocument();
    expect(screen.getByText('已过期')).toBeInTheDocument();
  });

  it('shows a clear error for corrupted input and does not crash the page', () => {
    render(<CertificateDetailPage now={fixedNow} />);
    parseInput(loadFixture('corrupted-cert.pem'));

    const errorBox = screen.getByTestId('parse-error');
    expect(errorBox).toBeInTheDocument();
    expect(errorBox).toHaveTextContent(/无法解析证书/);
    expect(errorBox).toHaveTextContent(/解析失败/);
    expect(screen.getByText('证书详情')).toBeInTheDocument();
    expect(screen.queryByTestId('cert-detail')).not.toBeInTheDocument();
  });

  it('shows a clear error for non-PEM text', () => {
    render(<CertificateDetailPage now={fixedNow} />);
    parseInput('definitely not a pem');

    const errorBox = screen.getByTestId('parse-error');
    expect(errorBox).toBeInTheDocument();
    expect(errorBox).toHaveTextContent(/未找到有效的 PEM 块/);
  });

  it('disables the parse button when the input is empty', () => {
    render(<CertificateDetailPage now={fixedNow} />);
    expect(screen.getByRole('button', { name: /解析证书/ })).toBeDisabled();
  });
});

describe('CertificateDetailPage validity evaluation', () => {
  // expired-cert.pem validity (from openssl x509 -dates): 2020-01-01 .. 2021-01-01 UTC
  it('shows notYetValid with days remaining when eval time is before notBefore', () => {
    render(<CertificateDetailPage now={fixedNow} />);
    parseInput(loadFixture('expired-cert.pem'));

    // 2019-12-27 00:00 UTC is exactly 5 days before 2020-01-01 00:00 UTC
    setEvalTime('2019-12-27T00:00');

    const summary = screen.getByTestId('validity-summary');
    expect(summary).toHaveAttribute('data-status', 'notYetValid');
    expect(summary).toHaveTextContent('尚未生效');
    expect(summary).toHaveTextContent('距离生效还有 5 天');
  });

  it('shows valid with days remaining when eval time is inside the window', () => {
    render(<CertificateDetailPage now={fixedNow} />);
    parseInput(loadFixture('expired-cert.pem'));

    // 2020-06-01 00:00 UTC; floor((2021-01-01 - 2020-06-01)/day) = 214 days
    setEvalTime('2020-06-01T00:00');

    const summary = screen.getByTestId('validity-summary');
    expect(summary).toHaveAttribute('data-status', 'valid');
    expect(summary).toHaveTextContent('当前有效');
    expect(summary).toHaveTextContent('还有 214 天过期');
  });

  it('shows expired with days since expiry when eval time is after notAfter', () => {
    render(<CertificateDetailPage now={fixedNow} />);
    parseInput(loadFixture('expired-cert.pem'));

    // 2021-01-06 00:00 UTC is exactly 5 days after 2021-01-01 00:00 UTC
    setEvalTime('2021-01-06T00:00');

    const summary = screen.getByTestId('validity-summary');
    expect(summary).toHaveAttribute('data-status', 'expired');
    expect(summary).toHaveTextContent('已经过期 5 天');
  });

  it('updates the result deterministically when the same eval time is re-selected', () => {
    render(<CertificateDetailPage now={fixedNow} />);
    parseInput(loadFixture('expired-cert.pem'));

    setEvalTime('2020-06-01T00:00');
    const first = screen.getByTestId('validity-summary').textContent;
    setEvalTime('2021-01-06T00:00');
    setEvalTime('2020-06-01T00:00');
    const second = screen.getByTestId('validity-summary').textContent;

    expect(second).toBe(first);
  });
});

describe('CertificateDetailPage persistence', () => {
  it('persists the last PEM and evaluation time to localStorage', () => {
    render(<CertificateDetailPage now={fixedNow} />);
    parseInput(loadFixture('expired-cert.pem'));
    setEvalTime('2020-06-01T00:00');

    expect(localStorage.getItem('certscope.detail.pem')).toBe(loadFixture('expired-cert.pem'));
    expect(localStorage.getItem('certscope.detail.evalTime')).toBe('2020-06-01T00:00');
  });

  it('restores the last PEM, evaluation time, and result after a page remount', () => {
    const pem = loadFixture('expired-cert.pem');

    const { unmount } = render(<CertificateDetailPage now={fixedNow} />);
    parseInput(pem);
    setEvalTime('2020-06-01T00:00');
    unmount();

    // Simulate a fresh page load: no `now` prop so it would default to current time,
    // but the persisted eval time must take precedence.
    render(<CertificateDetailPage />);

    const textarea = screen.getByPlaceholderText(/BEGIN CERTIFICATE/) as HTMLTextAreaElement;
    expect(textarea.value).toBe(pem);
    expect(screen.getByTestId('eval-time')).toHaveValue('2020-06-01T00:00');

    // The previously parsed result is restored (not the empty state)
    expect(screen.getByTestId('cert-detail')).toBeInTheDocument();
    const summary = screen.getByTestId('validity-summary');
    expect(summary).toHaveAttribute('data-status', 'valid');
    expect(summary).toHaveTextContent('还有 214 天过期');
  });
});
