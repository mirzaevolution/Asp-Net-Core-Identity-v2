using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using BasicCustomIdentity.Entities;
using System.Threading;

namespace BasicCustomIdentity
{
    public class BasicUserStore : IUserStore<BasicUser>, IUserPasswordStore<BasicUser>
    {
        private readonly BasicIdentityDbContext _context;

        public BasicUserStore(BasicIdentityDbContext context)
        {
            _context = context;
        }

        public async Task<IdentityResult> CreateAsync(BasicUser user, CancellationToken cancellationToken)
        {
            try
            {
                _context.BasicUsers.Add(user);
                if (await _context.SaveChangesAsync() > 0)
                    return IdentityResult.Success;
                return IdentityResult.Failed(new IdentityError() { Description = "Failed to create the user" });
            }
            catch(Exception ex)
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Description = ex.Message
                });
            }
        }

        public async Task<IdentityResult> DeleteAsync(BasicUser user, CancellationToken cancellationToken)
        {
            try
            {
                _context.BasicUsers.Remove(user);
                if (await _context.SaveChangesAsync() > 0)
                    return IdentityResult.Success;
                return IdentityResult.Failed(new IdentityError() { Description = "Failed to remove the user" });
            }
            catch (Exception ex)
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Description = ex.Message
                });
            }
        }

        public void Dispose()
        {
            _context.Dispose();
        }

        public async Task<BasicUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            var user = await _context.BasicUsers.FirstOrDefaultAsync(c => c.Id == userId);
            return user;
        }

        public async Task<BasicUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            var user = await _context.BasicUsers.FirstOrDefaultAsync(c => c.NormalizedUserName == normalizedUserName);
            return user;
        }

        public Task<string> GetNormalizedUserNameAsync(BasicUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.NormalizedUserName);
        }

        public Task<string> GetPasswordHashAsync(BasicUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.PasswordHash);
        }

        public Task<string> GetUserIdAsync(BasicUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.Id);
        }

        public Task<string> GetUserNameAsync(BasicUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.UserName);
        }

        public Task<bool> HasPasswordAsync(BasicUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(!String.IsNullOrEmpty(user.PasswordHash));
        }

        public Task SetNormalizedUserNameAsync(BasicUser user, string normalizedName, CancellationToken cancellationToken)
        {
            user.NormalizedUserName = normalizedName;
            return Task.CompletedTask;
        }

        public Task SetPasswordHashAsync(BasicUser user, string passwordHash, CancellationToken cancellationToken)
        {
            user.PasswordHash = passwordHash;
            return Task.CompletedTask;
        }

        public Task SetUserNameAsync(BasicUser user, string userName, CancellationToken cancellationToken)
        {
            user.UserName = userName;
            return Task.CompletedTask;
        }

        public async Task<IdentityResult> UpdateAsync(BasicUser user, CancellationToken cancellationToken)
        {
            try
            {
                _context.BasicUsers.Update(user);
                if (await _context.SaveChangesAsync() > 0)
                    return IdentityResult.Success;
                return IdentityResult.Failed(new IdentityError() { Description = "Failed to update the user" });
            }
            catch (Exception ex)
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Description = ex.Message
                });
            }
        }
    }
}
