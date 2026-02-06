// Package embedding provides cosine-similarity math for comparing feature
// vectors. All functions are pure arithmetic with no external dependencies.
package embedding

import "math"

// CosineSimilarity computes the cosine of the angle between two vectors.
// Both vectors must have the same length. If either vector has zero magnitude
// the function returns 0.0 to avoid division by zero.
func CosineSimilarity(a, b []float64) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0.0
	}

	var dot, normA, normB float64
	for i := range a {
		dot += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}

	if normA == 0 || normB == 0 {
		return 0.0
	}

	return dot / (math.Sqrt(normA) * math.Sqrt(normB))
}

// L2Normalize returns a new vector whose L2 (Euclidean) norm is 1.
// If the input vector has zero magnitude an all-zeros copy is returned.
func L2Normalize(v []float64) []float64 {
	out := make([]float64, len(v))

	var sum float64
	for _, x := range v {
		sum += x * x
	}

	if sum == 0 {
		return out
	}

	norm := math.Sqrt(sum)
	for i, x := range v {
		out[i] = x / norm
	}

	return out
}
