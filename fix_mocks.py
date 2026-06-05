import os

files_to_fix = [
    'backend/internal/api/handlers_report_test.go',
    'backend/internal/ml/training_dataset_test.go',
    'backend/internal/ml/wave2_test.go',
    'backend/internal/storage/sanitize_test.go',
]

stub = '''
func (r *REPO) SaveAgentEvent(ctx context.Context, scanID string, event model.ScanEvent) error { return nil }
func (r *REPO) ListAgentEvents(ctx context.Context, scanID string) ([]model.ScanEvent, error) { return nil, nil }
'''

repos = {
    'backend/internal/api/handlers_report_test.go': ['reportTestRepo'],
    'backend/internal/ml/training_dataset_test.go': ['datasetTestRepo'],
    'backend/internal/ml/wave2_test.go': ['fakeRepo'],
    'backend/internal/storage/sanitize_test.go': ['captureUpdateRepo'],
}

for file, repo_names in repos.items():
    with open(file, 'a') as f:
        for repo_name in repo_names:
            f.write(stub.replace('REPO', repo_name))

