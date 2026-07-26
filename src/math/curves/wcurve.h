//
// Created by M Lunkeit on 26.07.26.
//

#ifndef BASALT_WCURVE_H
#define BASALT_WCURVE_H

#include <stdint.h>
#include <stddef.h>

#define WCURVE_MAX_LIMBS 18

typedef struct {
    uint32_t x[WCURVE_MAX_LIMBS];
    uint32_t y[WCURVE_MAX_LIMBS];

    bool infinity;
} wcurve_point_t;

typedef struct {
    uint32_t x[WCURVE_MAX_LIMBS];
    uint32_t y[WCURVE_MAX_LIMBS];
    uint32_t z[WCURVE_MAX_LIMBS];

    bool infinity;
} wcurve_point_jacobian_t;

typedef struct {
    // prime modulus
    const uint32_t *p;
    const size_t len_p;
    // order of the weierstraß curve
    const uint32_t *n;
    const size_t len_n;

    // y^2=x^3+ax+b
    const uint32_t *a;
    const uint32_t *b;

    // generator point for the weierstraß curve
    const wcurve_point_t g;

    // flags for fast barrett reduction
    const uint32_t *mu_p;
    const uint32_t *mu_n;
} wcurve_spec_t;

bool wcurve_point_eq(
    const wcurve_point_t *a,
    const wcurve_point_t *b);

void wcurve_point_add(
    const wcurve_spec_t *wcurve,
    wcurve_point_t *result,
    const wcurve_point_t *a,
    const wcurve_point_t *b);

void wcurve_point_scale(
    const wcurve_spec_t *wcurve,
    wcurve_point_t *result,
    const wcurve_point_t *point,
    const uint32_t *k);

void wcurve_point_jacobian_add(
    const wcurve_spec_t *wcurve,
    wcurve_point_jacobian_t *result,
    const wcurve_point_jacobian_t *a,
    const wcurve_point_jacobian_t *b);

void wcurve_point_jacobian_scale(
    const wcurve_spec_t *wcurve,
    wcurve_point_jacobian_t *result,
    const wcurve_point_jacobian_t *point,
    const uint32_t *k);

void wcurve_point_affin_to_jacobian(
    const wcurve_spec_t *wcurve,
    wcurve_point_jacobian_t *jacobian,
    const wcurve_point_t *affin);

void wcurve_point_jacobian_to_affin(
    const wcurve_spec_t *wcurve,
    wcurve_point_t *affin,
    const wcurve_point_jacobian_t *jacobian);

#endif //BASALT_WCURVE_H
