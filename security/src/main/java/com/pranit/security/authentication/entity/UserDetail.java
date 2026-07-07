package com.pranit.security.authentication.entity;

import com.pranit.security.authentication.constants.Provider;
import com.pranit.security.authentication.profile.entity.UserProfile;
import com.pranit.security.authorization.entity.RoleDetail;
import com.pranit.security.shared.auditing.AuditEntity;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.persistence.Version;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import org.jspecify.annotations.NullMarked;
import org.springframework.modulith.NamedInterface;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Entity
@Table(
        name = "user_detail",
        schema = "authentication_schema",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_user_detail_username", columnNames = "username"),
                @UniqueConstraint(name = "uk_user_detail_email", columnNames = "email"),
                @UniqueConstraint(name = "uk_user_detail_oauth2_id", columnNames = "oauth2_id")
        },
        indexes = {
                @Index(name = "idx_user_detail_username", columnList = "username"),
                @Index(name = "idx_user_detail_email", columnList = "email"),
                @Index(name = "idx_user_detail_provider", columnList = "provider"),
                @Index(name = "idx_user_detail_oauth2_id", columnList = "oauth2_id"),
                @Index(name = "idx_user_detail_deleted", columnList = "deleted"),
                @Index(name = "idx_user_detail_enabled", columnList = "enabled"),
                @Index(name = "idx_user_detail_scheduled_deletion", columnList = "scheduled_deletion_at"),
                @Index(name = "idx_user_detail_deleted_schedule", columnList = "deleted, scheduled_deletion_at")
        }
)
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@SuperBuilder
@NamedInterface("user")
public final class UserDetail extends AuditEntity implements UserDetails, Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID userId;

    @Column(name = "username", nullable = false, length = 50)
    private String username;

    @Column(name = "password", length = 255)
    private String password;

    @Column(name = "email", nullable = false, length = 255)
    private String email;

    @OneToOne(
            mappedBy = "userDetail",
            cascade = CascadeType.ALL,
            orphanRemoval = true
    )
    private UserProfile userProfile;

    @Column(name = "oauth2_id", length = 150)
    private String oauth2Id;

    @Enumerated(EnumType.STRING)
    @Column(name = "provider", nullable = false, length = 20)
    @Builder.Default
    private Provider provider = Provider.LOCAL;

    @Column(name = "deleted", nullable = false)
    @Builder.Default
    private boolean deleted = false;

    @Column(name = "enabled", nullable = false)
    @Builder.Default
    private boolean enabled = false;

    @Column(name = "scheduled_deletion_at")
    private Instant scheduledDeletionAt;

    @Builder.Default
    private boolean AccountNonExpired = true;
    @Builder.Default
    private boolean AccountNonLocked = true;
    @Builder.Default
    private boolean CredentialsNonExpired = true;
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "user_roles",
            schema = "authorization_schema",
            joinColumns = @JoinColumn(
                    name = "user_id",
                    foreignKey = @ForeignKey(name = "fk_user_roles_user")
            ),
            inverseJoinColumns = @JoinColumn(
                    name = "role_id",
                    foreignKey = @ForeignKey(name = "fk_user_roles_role")
            )
    )
    @Builder.Default
    private Set<RoleDetail> roles = new LinkedHashSet<>();

    @Version
    private long version;

    @Override
    @NullMarked
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream()
                .flatMap(role -> Stream.concat(
                        Stream.of(new SimpleGrantedAuthority("ROLE_" + role.getRoleName())),
                        role.getPermissions()
                                .stream()
                                .map(permission ->
                                        new SimpleGrantedAuthority(permission.getPermissionCode()))
                ))
                .collect(Collectors.toUnmodifiableSet());
    }
}
